use crate::connection::preauth_hash::{PreauthHashState, PreauthHashValue};
use crate::session::{SessionAndChannel, SessionInfo};
use crate::sync_helpers::*;
use crate::{compression::*, msg_handler::*};
use binrw::prelude::*;
use bytes::Bytes;
use maybe_async::*;
use smb_msg::*;
use smb_transport::IoVec;
use std::{collections::HashMap, io::Cursor, sync::Arc};

use super::connection_info::ConnectionInfo;

/// The [`Transformer`] structure is responsible for transforming messages to and from bytes,
/// send over NetBios TCP connection.
///
/// See [`Transformer::transform_outgoing`] and [`Transformer::transform_incoming`] for transformation functions.
#[derive(Default)]
pub struct Transformer {
    /// Sessions opened from this connection.
    // This structure is performance-critical, so it uses RwLock to allow concurrent reads.
    // Writes are only done when a session is started or ended - which is *very* rare in high-performance scenarios.
    sessions: RwLock<HashMap<u64, Arc<RwLock<SessionAndChannel>>>>,

    config: RwLock<TransformerConfig>,

    /// Connection-level preauth integrity hash (SMB 3.1.1). The
    /// transformer is the single authoritative owner per MS-SMB2
    /// §3.1.4.2: ingested automatically from Negotiate / SessionSetup
    /// plain bytes during `transform_outgoing` / `transform_incoming`,
    /// and surfaced via [`Self::snapshot_preauth_finalized`] for
    /// signing-key derivation during the final SessionSetup round.
    ///
    /// Empty before [`Self::negotiated`] runs; seeded from
    /// `ConnectionInfo::preauth_hash` (which already includes the
    /// Negotiate Req + Resp) at that point.
    preauth_hash: Mutex<PreauthHashState>,
}

#[derive(Default, Debug)]
struct TransformerConfig {
    /// Compressors for this connection.
    compress: Option<(Compressor, Decompressor)>,

    negotiated: bool,

    /// Cached snapshot of the negotiated dialect/signing/encryption
    /// parameters. Populated by [`Transformer::negotiated`] and read by
    /// the setup-phase signing path so the transformer doesn't need to
    /// re-borrow `ConnectionInfo` from the worker on every send.
    conn_info: Option<Arc<ConnectionInfo>>,
}

#[maybe_async(AFIT)]
impl Transformer {
    /// Notifies that the connection negotiation has been completed,
    /// with the given [`ConnectionInfo`].
    pub async fn negotiated(&self, neg_info: &Arc<ConnectionInfo>) -> crate::Result<()> {
        {
            let config = self.config.read().await?;
            if config.negotiated {
                return Err(crate::Error::InvalidState(
                    "Connection is already negotiated!".into(),
                ));
            }
        }

        let mut config = self.config.write().await?;
        if neg_info.dialect.supports_compression() && neg_info.config.compression_enabled {
            let compress = neg_info.negotiation.compression.as_ref().map(|c| {
                let caps = Arc::new(c.clone());
                (Compressor::new(&caps), Decompressor::new(&caps))
            });
            config.compress = compress;
        }

        // Seed the connection-level preauth hash from the value the
        // negotiator built out of the Negotiate Req + Resp wire bytes.
        // From now on the transformer is the sole owner: all subsequent
        // SessionSetup Req/Resp ingestion happens inside
        // `transform_outgoing` / `transform_incoming`.
        *self.preauth_hash.lock().await? = neg_info.preauth_hash.clone();

        config.conn_info = Some(neg_info.clone());
        config.negotiated = true;

        Ok(())
    }

    /// Returns a clone of the current preauth hash, advanced to its
    /// `Finished` form for key-derivation use. `Ok(None)` is returned
    /// when the negotiated dialect doesn't support preauth integrity
    /// (i.e. anything below SMB 3.1.1).
    ///
    /// This is the public surface for the session-setup driver: it
    /// invokes this after the final SessionSetup Request has been
    /// dispatched (the transformer auto-ingested the plain bytes during
    /// `transform_outgoing`), and uses the value to derive the channel
    /// SigningKey.
    pub async fn snapshot_preauth_finalized(&self) -> crate::Result<Option<PreauthHashValue>> {
        let snapshot = self.preauth_hash.lock().await?.clone();
        match snapshot.finish()? {
            PreauthHashState::Finished(v) => Ok(Some(v)),
            PreauthHashState::Unsupported => Ok(None),
            PreauthHashState::InProgress(_) => Err(crate::Error::InvalidState(
                "PreauthHashState::finish() returned InProgress — should be unreachable".into(),
            )),
        }
    }

    /// Cached `ConnectionInfo` captured by `negotiated`. None before
    /// negotiation completes. Used by the setup-phase signing path
    /// (S4-T3) to derive the dialect / signing algorithm without
    /// re-borrowing from the worker on every send.
    #[allow(dead_code)] // wired up in S4-T3
    async fn conn_info(&self) -> crate::Result<Option<Arc<ConnectionInfo>>> {
        Ok(self.config.read().await?.conn_info.clone())
    }

    /// Derive a one-shot [`MessageSigner`] for the final SessionSetup
    /// Request, using the snapshot of the preauth hash that already
    /// includes this request's plain bytes (auto-ingested above) and
    /// the GSS-supplied SessionKey provided by the setup driver.
    ///
    /// Mirrors `ChannelInfo::new`'s key derivation so the signer is
    /// byte-identical to the one the server independently derives.
    async fn derive_setup_phase_signer(
        &self,
        session_key: &crate::crypto::KeyToDerive,
    ) -> crate::Result<crate::session::MessageSigner> {
        let conn_info = self.conn_info().await?.ok_or_else(|| {
            crate::Error::InvalidState(
                "setup-phase signing requested before `negotiated` ran".into(),
            )
        })?;
        let preauth_snapshot = self.snapshot_preauth_finalized().await?;
        let channel_info = crate::session::ChannelInfo::new(
            // The id only matters for in-session channel tracking; a
            // setup-phase signer is anonymous (no session table entry
            // yet), so any sentinel will do.
            u32::MAX,
            session_key,
            &preauth_snapshot,
            &conn_info,
        )?;
        Ok(channel_info.signer()?.clone())
    }

    /// MS-SMB2 §3.1.4.2: client-side rule for which **outgoing**
    /// messages get folded into Connection.PreauthIntegrityHashValue.
    fn participates_in_preauth_outgoing(header: &Header) -> bool {
        matches!(header.command, Command::Negotiate | Command::SessionSetup)
    }

    /// MS-SMB2 §3.1.4.2: client-side rule for which **incoming**
    /// messages get folded into the hash. Negotiate Response is always
    /// included; SessionSetup Response only when it carries
    /// MORE_PROCESSING_REQUIRED (i.e. it isn't the final ACK that
    /// closes the chain).
    fn participates_in_preauth_incoming(header: &Header) -> bool {
        match header.command {
            Command::Negotiate => true,
            Command::SessionSetup => header.status == Status::MoreProcessingRequired as u32,
            _ => false,
        }
    }

    /// Notifies that a session has started.
    pub async fn session_started(
        &self,
        session: &Arc<RwLock<SessionAndChannel>>,
    ) -> crate::Result<()> {
        let rconfig = self.config.read().await?;
        if !rconfig.negotiated {
            return Err(crate::Error::InvalidState(
                "Connection is not negotiated yet!".to_string(),
            ));
        }

        let session_id = { session.read().await?.session_id };
        self.sessions
            .write()
            .await?
            .insert(session_id, session.clone());

        tracing::trace!(
            "Session {} started and inserted to worker {:p}.",
            session_id,
            self
        );

        Ok(())
    }

    /// Notifies that a session has ended.
    pub async fn session_ended(
        &self,
        session: &Arc<RwLock<SessionAndChannel>>,
    ) -> crate::Result<()> {
        let session_id = { session.read().await?.session_id };
        self.sessions
            .write()
            .await?
            .remove(&session_id)
            .ok_or(crate::Error::InvalidState(format!(
                "Session {session_id} not found!",
            )))?;

        tracing::trace!(
            "Session {} ended and removed from worker {:p}.",
            session_id,
            self
        );

        Ok(())
    }

    /// (Internal)
    ///
    /// Locates the current channel per the provded session ID,
    /// and invokes the provided closure with the channel information.
    ///
    /// Note: this function WILL deadlock if any lock attempt is performed within the closure on `self.sessions`.
    #[maybe_async]
    #[inline]
    async fn _with_channel<F, R>(&self, session_id: u64, f: F) -> crate::Result<R>
    where
        F: FnOnce(&SessionAndChannel) -> crate::Result<R>,
    {
        let sessions = self.sessions.read().await?;
        let session = sessions
            .get(&session_id)
            .ok_or(crate::Error::InvalidState(format!(
                "Session {session_id} not found!",
            )))?;
        let session = session.read().await?;
        f(&session)
    }

    /// (Internal)
    ///
    /// Locates the current session per the provided session ID,
    /// and invokes the provided closure with the session information.
    ///
    /// Note: this function WILL deadlock if any lock attempt is performed within the closure on `self.sessions`.
    #[maybe_async]
    #[inline]
    async fn _with_session<F, R>(&self, session_id: u64, f: F) -> crate::Result<R>
    where
        F: FnOnce(&SessionInfo) -> crate::Result<R>,
    {
        let sessions = self.sessions.read().await?;
        let session = sessions
            .get(&session_id)
            .ok_or(crate::Error::InvalidState(format!(
                "Session {session_id} not found!",
            )))?;
        let session = session.read().await?;
        let session_info = session.session.read().await?;
        f(&session_info)
    }

    /// Build the wire bytes for an SMB2 compound chain (MS-SMB2 3.2.4.1.4):
    /// multiple SMB2 commands concatenated in one TCP send, each with its own
    /// header carrying a `NextCommand` offset to the next member.
    ///
    /// Behavior summary:
    /// - Each member is serialized independently (header + content).
    /// - Each header's `next_command` is set to the 8-byte-aligned length of
    ///   that member (0 for the last). Headers are re-written to capture this.
    /// - Each member is then padded to 8-byte alignment as required by the spec.
    /// - Signing is per-member: each header's signature is computed over just
    ///   that member's byte slice (header with signature=0 + body), then written
    ///   back into the header. All members must have the same `signed` flag on
    ///   the first member (used as the chain-wide policy).
    /// - The resulting [`IoVec`] is the concatenation of each member's bytes
    ///   in order, ready for the transport to write.
    ///
    /// **Constraints for the current minimal implementation:**
    /// - No encryption.
    /// - No compression.
    /// - No `additional_data` zero-copy bodies (data is whatever each
    ///   member's `PlainRequest` serializes to).
    /// - Caller must have already populated `header.message_id`,
    ///   `tree_id`, `session_id`, and `credit_charge` / `credit_request`
    ///   per member (typically done by `Connection::process_sequence_outgoing`
    ///   on each message before this call).
    /// - Caller is responsible for setting `flags.related_operations` on the
    ///   2nd..Nth members and the `0xFF…FF` sentinel `FileId` on commands that
    ///   want to chain context from a prior Create.
    ///
    /// Returns `Err(InvalidArgument)` for an empty `msgs` slice or any
    /// member that requests encryption / additional_data.
    pub async fn transform_outgoing_compound(
        &self,
        mut msgs: Vec<OutgoingMessage>,
    ) -> crate::Result<IoVec> {
        if msgs.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "compound chain requires at least one message".to_string(),
            ));
        }
        for (i, m) in msgs.iter().enumerate() {
            if m.encrypt {
                return Err(crate::Error::InvalidArgument(format!(
                    "compound member {i}: encryption is not supported in the current minimal compound path",
                )));
            }
            if m.additional_data.is_some() {
                return Err(crate::Error::InvalidArgument(format!(
                    "compound member {i}: additional_data is not supported in compound mode",
                )));
            }
        }

        // 1. Serialize each member's bytes (header + content). Header still
        //    has its old `next_command = 0` here; we rewrite it in step 2.
        let mut member_bufs: Vec<Vec<u8>> = Vec::with_capacity(msgs.len());
        for m in &msgs {
            let mut buf = Vec::with_capacity(Header::STRUCT_SIZE + 256);
            m.message.write(&mut Cursor::new(&mut buf))?;
            member_bufs.push(buf);
        }

        // 2. Compute next_command offsets and rewrite each member's header bytes.
        //    For member i (except last): next_command = 8-byte-aligned len of member i's buffer.
        //    For last member: next_command = 0 (already).
        let last = msgs.len() - 1;
        for i in 0..last {
            let aligned = (member_bufs[i].len() + 7) & !7usize;
            msgs[i].message.header.next_command = u32::try_from(aligned).map_err(|_| {
                crate::Error::InvalidState(format!(
                    "compound member {i}: aligned size {aligned} does not fit in u32",
                ))
            })?;
            // Rewrite the header bytes in-place with the updated next_command.
            let mut header_bytes = [0u8; Header::STRUCT_SIZE];
            msgs[i]
                .message
                .header
                .write(&mut Cursor::new(&mut header_bytes[..]))?;
            member_bufs[i][..Header::STRUCT_SIZE].copy_from_slice(&header_bytes);
        }

        // 3. Pad each non-last member to 8-byte alignment FIRST. The
        //    `next_command` offset we set in step 2 is the padded length,
        //    and per MS-SMB2 3.1.4.1 the per-member signature MUST cover
        //    the full byte range the server sees as "this command", i.e.
        //    the padded buffer. Signing must therefore happen AFTER
        //    padding so the HMAC input matches what the receiver
        //    re-hashes during verification.
        for buf in member_bufs.iter_mut().take(last) {
            let aligned = (buf.len() + 7) & !7usize;
            buf.resize(aligned, 0);
        }

        // 4. Sign each member if signing is requested (per-member, over
        //    that member's padded bytes). We snapshot the signer once
        //    and reuse it for each member (MessageSigner clone is cheap
        //    — no heap alloc).
        //
        // Sign policy is chain-wide: the first member's `signed` flag is
        // the source of truth. We *also* enforce that every member
        // agrees with it — mixing signed and unsigned members in a
        // single chain produces a payload the server will reject as
        // soon as it verifies any member's signature (signed members
        // need a real signature, unsigned ones must carry the all-zero
        // sentinel). Catching this here yields a clearer error than the
        // server-side STATUS_ACCESS_DENIED that would otherwise come back.
        let should_sign = msgs[0].message.header.flags.signed();
        if msgs
            .iter()
            .any(|m| m.message.header.flags.signed() != should_sign)
        {
            return Err(crate::Error::InvalidArgument(
                "compound chain has inconsistent `signed` flags across members; \
                 all members must opt in or opt out together"
                    .to_string(),
            ));
        }
        if should_sign {
            let session_id = msgs[0].message.header.session_id;
            let signer = self
                ._with_channel(session_id, |session| {
                    let channel_info =
                        session
                            .channel
                            .as_ref()
                            .ok_or(crate::Error::TranformFailed(TransformError {
                                outgoing: true,
                                phase: TransformPhase::SignVerify,
                                session_id: Some(session_id),
                                why: "Compound message is signed, but no channel signer is set up",
                                msg_id: None,
                            }))?;
                    Ok(channel_info.signer()?.clone())
                })
                .await?;

            for i in 0..msgs.len() {
                let mut iov: IoVec = IoVec::from(std::mem::take(&mut member_bufs[i]));
                let mut signer = signer.clone();
                signer.sign_message(&mut msgs[i].message.header, &mut iov)?;
                // After sign_message, iov[0] holds the buffer with the signature
                // written back into the header. Move it back into member_bufs
                // without copying (IoVecBuf::Owned -> Vec via mem::take).
                //
                // We rely on the signer leaving the IoVec as a single owned
                // segment (sign_message writes the signature back into the
                // header bytes that live in iov[0] — no splitting). If a
                // future signer change starts appending segments, only
                // iov[0] would be taken back here and the trailing bytes
                // would silently drop on the floor. Guard against that
                // regression with an explicit length check.
                if iov.len() != 1 {
                    return Err(crate::Error::InvalidState(format!(
                        "signer split compound member buffer into {} segments; \
                         exactly 1 expected",
                        iov.len()
                    )));
                }
                match &mut iov[0] {
                    smb_transport::IoVecBuf::Owned(v) => {
                        member_bufs[i] = std::mem::take(v);
                    }
                    smb_transport::IoVecBuf::Shared(_) => {
                        return Err(crate::Error::InvalidState(
                            "signed compound member buffer was not owned".to_string(),
                        ));
                    }
                }
                tracing::trace!(
                    "Compound member {i} (msg_id {}) signed (signature={}).",
                    msgs[i].message.header.message_id,
                    msgs[i].message.header.signature,
                );
            }
        }

        // 5. Concatenate into the output IoVec. Each member is its own
        //    owned buffer — the transport will gather them on send.
        let mut out = IoVec::default();
        for buf in member_bufs {
            out.add_owned(buf);
        }
        Ok(out)
    }

    /// Transforms an outgoing message to a raw SMB message.
    pub async fn transform_outgoing(&self, mut msg: OutgoingMessage) -> crate::Result<IoVec> {
        let should_encrypt = msg.encrypt;
        let should_sign = msg.message.header.flags.signed();
        let session_id = msg.message.header.session_id;

        let mut outgoing_data = IoVec::default();
        // Plain header + content (signature is still zero at this point —
        // `sign_message` patches it back into the buffer below, after the
        // preauth-hash ingest sees the unsigned bytes).
        {
            let buffer = outgoing_data.add_owned(Vec::with_capacity(Header::STRUCT_SIZE));
            msg.message.write(&mut Cursor::new(buffer))?;
        }

        // Per MS-SMB2 §3.1.4.2, Negotiate Requests and *all*
        // SessionSetup Requests participate in the connection-level
        // preauth integrity hash. We ingest the plain (signature=0)
        // bytes here so the hash is identical to what the server
        // computes on receive. Doing it inside the transformer
        // centralises the contract: the session-setup driver doesn't
        // need to know which messages count.
        if Self::participates_in_preauth_outgoing(&msg.message.header) {
            if let Some(plain) = outgoing_data.first() {
                let mut hash = self.preauth_hash.lock().await?;
                // Clone-then-replace: if `next` errors we want to keep
                // the previous hash state intact, not corrupt it to a
                // default `Unsupported`.
                *hash = hash.clone().next(plain)?;
            }
        }

        // Additional data, if any (zero-copy via Bytes)
        if let Some(data) = msg.additional_data.take() {
            if !data.is_empty() {
                outgoing_data.add_bytes(data);
            }
        }

        // 1. Sign
        if should_sign {
            debug_assert!(
                !should_encrypt,
                "Should not sign and encrypt at the same time!"
            );

            let mut signer = if let Some(Protection::SnapshotKdfSign { session_key }) =
                msg.security.take()
            {
                // Setup-phase path: the final SessionSetup Request signs
                // itself with a one-shot key derived from
                // KDF(SessionKey, finalized preauth hash AFTER this
                // request's plain bytes), per MS-SMB2 §3.2.4.1.7. No
                // channel exists in `session_state` yet (it'll be
                // installed by the driver immediately after dispatch
                // for the response-verify path).
                self.derive_setup_phase_signer(&session_key).await?
            } else {
                self._with_channel(session_id, |session| {
                    let channel_info =
                        session
                            .channel
                            .as_ref()
                            .ok_or(crate::Error::TranformFailed(TransformError {
                                outgoing: true,
                                phase: TransformPhase::SignVerify,
                                session_id: Some(session_id),
                                why: "Message is required to be signed, but no channel is set up!",
                                msg_id: Some(msg.message.header.message_id),
                            }))?;

                    Ok(channel_info.signer()?.clone())
                })
                .await?
            };

            signer.sign_message(&mut msg.message.header, &mut outgoing_data)?;

            tracing::debug!(
                "Message #{} signed (signature={}).",
                msg.message.header.message_id,
                msg.message.header.signature
            );
        };

        // 2. Compress
        const COMPRESSION_THRESHOLD: usize = 1024;
        outgoing_data = {
            if msg.compress && outgoing_data.total_size() > COMPRESSION_THRESHOLD {
                let rconfig = self.config.read().await?;
                if let Some(compress) = &rconfig.compress {
                    // Build a vector of the entire data. In the future, this may be optimized to avoid copying.
                    // currently, there's not chained compression, and copy will occur anyway.
                    outgoing_data.consolidate();
                    let compressed =
                        compress.0.compress(outgoing_data.first().ok_or_else(|| {
                            crate::Error::InvalidState(
                                "Outgoing data is empty after consolidation.".to_string(),
                            )
                        })?)?;

                    let mut compressed_result = IoVec::default();
                    let write_compressed =
                        compressed_result.add_owned(Vec::with_capacity(compressed.total_size()));
                    compressed.write(&mut Cursor::new(write_compressed))?;
                    compressed_result
                } else {
                    outgoing_data
                }
            } else {
                outgoing_data
            }
        };

        // 3. Encrypt
        if should_encrypt {
            debug_assert!(should_encrypt && !should_sign);

            let encrypted_header = self
                ._with_session(session_id, |session| {
                    let encryptor = session.encryptor()?.ok_or(crate::Error::TranformFailed(
                        TransformError {
                            outgoing: true,
                            phase: TransformPhase::EncryptDecrypt,
                            session_id: Some(session_id),
                            why: "Message is required to be encrypted, but no encryptor is set up!",
                            msg_id: Some(msg.message.header.message_id),
                        },
                    ))?;
                    encryptor.encrypt_message(&mut outgoing_data, session_id)
                })
                .await?;

            let write_encryption_header =
                outgoing_data.insert_owned(0, Vec::with_capacity(EncryptedHeader::STRUCTURE_SIZE));

            encrypted_header.write(&mut Cursor::new(write_encryption_header))?;
        }

        Ok(outgoing_data)
    }

    /// Transforms an incoming message buffer to one or more [`IncomingMessage`]s,
    /// supporting SMB2 compound responses.
    ///
    /// SMB2 compound responses chain multiple commands' responses into a single
    /// TCP frame using the [`Header::next_command`] field (MS-SMB2 3.2.5.1.9 /
    /// 3.3.4.1.5). Each member has its own header (including its own signature
    /// when signing is on); the whole chain is encrypted/compressed as a unit if
    /// either transformation is active.
    ///
    /// This method:
    /// 1. Decrypts the chain (one shot) if [`Response::Encrypted`].
    /// 2. Decompresses (one shot) if [`Response::Compressed`].
    /// 3. Walks the resulting plain bytes, parsing one [`PlainResponse`] per
    ///    NextCommand-delimited section, verifying each section's signature
    ///    against just its own byte slice.
    ///
    /// Returns a `Vec` with one entry per member (length 1 in the common,
    /// non-compound case). Member order matches the on-wire order, which the
    /// server is required to preserve relative to the request chain (MS-SMB2
    /// 3.3.5.2.7).
    pub async fn transform_incoming_all(&self, data: Bytes) -> crate::Result<Vec<IncomingMessage>> {
        let message = Response::try_from(data.as_ref())?;
        let mut form = MessageForm::default();

        // 1. Decrypt (whole chain)
        let (message, raw) = if let Response::Encrypted(encrypted_message) = message {
            let session_id = encrypted_message.header.session_id;
            form.encrypted = true;
            let (msg, vec) = self
                ._with_session(session_id, |session| {
                    let decryptor = session.decryptor()?.ok_or(crate::Error::TranformFailed(
                        TransformError {
                            outgoing: false,
                            phase: TransformPhase::EncryptDecrypt,
                            session_id: Some(session_id),
                            why: "Message is required to be encrypted, but no decryptor is set up!",
                            msg_id: None,
                        },
                    ))?;
                    decryptor.decrypt_message(encrypted_message)
                })
                .await?;
            (msg, Bytes::from(vec))
        } else {
            (message, data)
        };

        // 2. Decompress (whole chain)
        debug_assert!(!matches!(message, Response::Encrypted(_)));
        let (message, raw) = if let Response::Compressed(compressed_message) = message {
            let rconfig = self.config.read().await?;
            form.compressed = true;
            match &rconfig.compress {
                Some(compress) => {
                    let (msg, vec) = compress.1.decompress(&compressed_message)?;
                    (msg, Bytes::from(vec))
                }
                None => {
                    return Err(crate::Error::TranformFailed(TransformError {
                        outgoing: false,
                        phase: TransformPhase::CompressDecompress,
                        session_id: None,
                        why: "Compression is requested, but no decompressor is set up!",
                        msg_id: None,
                    }));
                }
            }
        } else {
            (message, raw)
        };

        let plain = match message {
            Response::Plain(p) => p,
            _ => {
                return Err(crate::Error::InvalidMessage(
                    "Expected plain message after decryption/decompression".to_string(),
                ));
            }
        };

        // 3. Walk the compound chain (or return single).
        //    `next_command == 0` means this is the last (or only) member.
        let mut out: Vec<IncomingMessage> = Vec::new();
        let mut current = plain;
        let mut remaining = raw;
        loop {
            let next_offset = current.header.next_command as usize;
            // The slice belonging to *this* member is `remaining[..next_offset]`
            // when there's another command after it, else the whole rest of
            // `remaining`. Signing/verification is per-member over this slice.
            let this_slice = if next_offset > 0 {
                if next_offset > remaining.len() {
                    return Err(crate::Error::InvalidMessage(format!(
                        "Compound NextCommand offset {next_offset} exceeds remaining buffer {}",
                        remaining.len()
                    )));
                }
                remaining.slice(0..next_offset)
            } else {
                remaining.clone()
            };

            let mut member_form = form;
            if let Err(e) = self
                .verify_plain_incoming(&mut current, &this_slice, &mut member_form)
                .await
            {
                tracing::error!("Failed to verify compound member message: {e:?}");
                return Err(crate::Error::TranformFailed(TransformError {
                    outgoing: false,
                    phase: TransformPhase::SignVerify,
                    session_id: Some(current.header.session_id),
                    why: "Failed to verify compound member signature!",
                    msg_id: Some(current.header.message_id),
                }));
            }
            out.push(IncomingMessage::new(current, this_slice, member_form));

            if next_offset == 0 {
                break;
            }
            remaining = remaining.slice(next_offset..);
            // Parse next member's header + content from the new slice start.
            let next_resp = Response::try_from(remaining.as_ref())?;
            current = match next_resp {
                Response::Plain(p) => p,
                _ => {
                    return Err(crate::Error::InvalidMessage(
                        "Compound chain member must be a plain SMB2 response \
                         (encryption/compression apply to the whole chain only)"
                            .to_string(),
                    ));
                }
            };
        }

        Ok(out)
    }

    /// Transforms an incoming message buffer to an [`IncomingMessage`].
    ///
    /// Accepts `Bytes` for zero-copy slicing of the raw data in downstream consumers.
    pub async fn transform_incoming(&self, data: Bytes) -> crate::Result<IncomingMessage> {
        let message = Response::try_from(data.as_ref())?;

        let mut form = MessageForm::default();

        // 3. Decrypt
        let (message, raw) = if let Response::Encrypted(encrypted_message) = message {
            let session_id = encrypted_message.header.session_id;

            form.encrypted = true;
            let (msg, vec) = self
                ._with_session(session_id, |session| {
                    let decryptor = session.decryptor()?.ok_or(crate::Error::TranformFailed(
                        TransformError {
                            outgoing: false,
                            phase: TransformPhase::EncryptDecrypt,
                            session_id: Some(session_id),
                            why: "Message is required to be encrypted, but no decryptor is set up!",
                            msg_id: None,
                        },
                    ))?;
                    decryptor.decrypt_message(encrypted_message)
                })
                .await?;
            // Decryption returns a new Vec<u8>, convert to Bytes
            (msg, Bytes::from(vec))
        } else {
            (message, data)
        };

        // 2. Decompress
        debug_assert!(!matches!(message, Response::Encrypted(_)));
        let (message, raw) = if let Response::Compressed(compressed_message) = message {
            let rconfig = self.config.read().await?;
            form.compressed = true;
            match &rconfig.compress {
                Some(compress) => {
                    let (msg, vec) = compress.1.decompress(&compressed_message)?;
                    // Decompression returns a new Vec<u8>, convert to Bytes
                    (msg, Bytes::from(vec))
                }
                None => {
                    return Err(crate::Error::TranformFailed(TransformError {
                        outgoing: false,
                        phase: TransformPhase::CompressDecompress,
                        session_id: None,
                        why: "Compression is requested, but no decompressor is set up!",
                        msg_id: None,
                    }));
                }
            }
        } else {
            (message, raw)
        };

        let mut message = match message {
            Response::Plain(message) => message,
            _ => {
                return Err(crate::Error::InvalidMessage(
                    "Expected plain message after decryption/decompression".to_string(),
                ));
            }
        };

        // Per MS-SMB2 §3.1.4.2 fold qualifying responses into the
        // connection-level preauth hash *before* signature verification:
        // (a) so the Final SessionSetup Response we're about to verify
        // sees the same hash the server used to derive its signing key,
        // and (b) so future channel-binding setups picking up the
        // snapshot see Negotiate Resp / intermediate SessionSetup Resp
        // bytes included.
        if Self::participates_in_preauth_incoming(&message.header) {
            let mut hash = self.preauth_hash.lock().await?;
            // Clone-then-replace; see `transform_outgoing` for rationale.
            *hash = hash.clone().next(&raw)?;
        }

        // Verify signature directly from raw bytes (no IoVec copy needed).
        if let Err(e) = self
            .verify_plain_incoming(&mut message, &raw, &mut form)
            .await
        {
            tracing::error!("Failed to verify incoming message: {e:?}");
            return Err(crate::Error::TranformFailed(TransformError {
                outgoing: false,
                phase: TransformPhase::SignVerify,
                session_id: Some(message.header.session_id),
                why: "Failed to verify incoming message!",
                msg_id: Some(message.header.message_id),
            }));
        }

        Ok(IncomingMessage::new(message, raw, form))
    }

    /// (Internal)
    ///
    /// A helper method to verify the incoming message.
    /// This method is used to verify the signature of the incoming message,
    /// if such verification is required.
    #[maybe_async]
    async fn verify_plain_incoming(
        &self,
        message: &mut PlainResponse,
        raw: &[u8],
        form: &mut MessageForm,
    ) -> crate::Result<()> {
        // Check if signing check is required.
        if form.encrypted
            || message.header.message_id == u64::MAX
            || message.header.status == Status::Pending as u32
            || !(message.header.flags.signed() || self.is_message_signed_ksmbd(message).await)
        {
            return Ok(());
        }

        // Verify signature (if required, according to the spec)
        let session_id = message.header.session_id;
        let mut signer = self
            ._with_channel(session_id, |session| {
                let channel_info = session
                    .channel
                    .as_ref()
                    .ok_or(crate::Error::TranformFailed(TransformError {
                        outgoing: false,
                        phase: TransformPhase::SignVerify,
                        session_id: Some(session_id),
                        why: "Message is required to be signed, but no channel is set up!",
                        msg_id: Some(message.header.message_id),
                    }))?;

                Ok(channel_info.signer()?.clone())
            })
            .await?;

        signer.verify_signature(&mut message.header, raw)?;
        tracing::debug!(
            "Message #{} verified (signature={}).",
            message.header.message_id,
            message.header.signature
        );
        form.signed = true;
        Ok(())
    }

    /// (Internal)
    ///
    /// ksmbd multichannel setup compatibility check.
    ///
    // ksmbd has a subtle, but irritating bug, where it does not set the "signed" flag
    // for responses during multi channel session setups. To resolve this, we check if the
    // current channel is defined as "binding-only" channel. The feature `ksmbd-multichannel-compat`
    // must also be enabled, or else this code will not be compiled.
    // This behavior is actually against the spec - MS-SMB2 3.2.4.1.1:
    // > "If the client signs the request, it MUST set the SMB2_FLAGS_SIGNED bit in the Flags field of the SMB2 header."
    #[maybe_async]
    async fn is_message_signed_ksmbd(&self, _message: &PlainResponse) -> bool {
        #[cfg(feature = "ksmbd-multichannel-compat")]
        {
            if _message.header.command != Command::SessionSetup || _message.header.signature == 0 {
                return false;
            }

            let session_id = _message.header.session_id;
            let is_binding = self
                ._with_channel(session_id, |session| {
                    let channel_info = session.channel.as_ref().ok_or(crate::Error::Other(
                        "Get channel info for ksmbd sign test failed",
                    ))?;

                    Ok(channel_info.is_binding())
                })
                .await;

            return matches!(is_binding, Ok(true));
        }

        #[cfg(not(feature = "ksmbd-multichannel-compat"))]
        return false;
    }
}

/// An error that can occur during the transformation of messages.
#[derive(Debug)]
pub struct TransformError {
    /// If true, the error occurred while transforming an outgoing message.
    /// If false, it occurred while transforming an incoming message.
    pub outgoing: bool,
    pub phase: TransformPhase,
    pub session_id: Option<u64>,
    pub why: &'static str,
    /// If a message ID is available, it will be set here,
    /// for error-handling purposes.
    pub msg_id: Option<u64>,
}

impl std::fmt::Display for TransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let direction = if self.outgoing {
            "outgoing"
        } else {
            "incoming"
        };
        write!(
            f,
            "Failed to transform {direction} message: {:?} (session_id: {:?}) - {}",
            self.phase, self.session_id, self.why
        )
    }
}

/// The phase of the transformation process.
#[derive(Debug)]
pub enum TransformPhase {
    /// Initial to/from bytes.
    EncodeDecode,
    /// Signature calculation and verification.
    SignVerify,
    /// Compression and decompression.
    CompressDecompress,
    /// Encryption and decryption.
    EncryptDecrypt,
}
