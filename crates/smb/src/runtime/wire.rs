use crate::connection::preauth_hash::{PreauthHashState, PreauthHashValue};
use crate::session::{MessageDecryptor, MessageEncryptor, MessageSigner, SessionAndChannel};
use crate::{command::*, compression::*};
use binrw::prelude::*;
use bytes::Bytes;
use smb_msg::*;
use smb_transport::SendFrame;
use std::sync::Arc;
use std::{collections::HashMap, io::Cursor};
use tokio::sync::{Mutex, RwLock};

use crate::connection::connection_info::ConnectionInfo;

/// The [`WirePipeline`] structure is responsible for transforming messages to and from bytes,
/// send over NetBios TCP connection.
///
/// See [`WirePipeline::transform_outgoing`] and [`WirePipeline::transform_incoming`] for transformation functions.
#[derive(Default)]
pub struct WirePipeline {
    /// Sessions opened from this connection.
    // This structure is performance-critical, so it uses RwLock to allow concurrent reads.
    // Writes are only done when a session is started or ended - which is *very* rare in high-performance scenarios.
    //
    // The value is `Arc<SessionAndChannel>` (no inner `RwLock`): T3
    // collapsed the previously-nested per-session RwLock into the
    // entry's set-once `ArcSwapOption<ChannelInfo>` slot plus an
    // `Arc<RwLock<SessionInfo>>` that is still kept (state machine).
    sessions: RwLock<HashMap<u64, Arc<SessionAndChannel>>>,

    config: RwLock<WirePipelineConfig>,

    /// Connection-level preauth integrity hash (SMB 3.1.1). The
    /// wire pipeline is the single authoritative owner per MS-SMB2
    /// §3.1.4.2: ingested automatically from Negotiate / SessionSetup
    /// plain bytes during `transform_outgoing` / `transform_incoming`,
    /// and surfaced via [`Self::snapshot_preauth_finalized`] for
    /// signing-key derivation during the final SessionSetup round.
    ///
    /// Empty before [`Self::negotiated`] runs; seeded from
    /// `ConnectionInfo::preauth_hash` (which already includes the
    /// Negotiate Req + Resp) at that point.
    preauth_hash: Mutex<PreauthHashState>,

    /// One-shot signer bridging the final SessionSetup request/response
    /// race before the primary channel is installed in the session table.
    setup_signers: Mutex<HashMap<u64, MessageSigner>>,
}

#[derive(Default, Debug)]
struct WirePipelineConfig {
    /// Compressors for this connection.
    compress: Option<(Compressor, Decompressor)>,

    negotiated: bool,

    /// Cached snapshot of the negotiated dialect/signing/encryption
    /// parameters. Populated by [`WirePipeline::negotiated`] and read by
    /// the setup-phase signing path so the wire pipeline doesn't need to
    /// re-borrow `ConnectionInfo` from the generation_runtime on every send.
    conn_info: Option<Arc<ConnectionInfo>>,
}

impl WirePipeline {
    /// Notifies that the connection negotiation has been completed,
    /// with the given [`ConnectionInfo`].
    pub async fn negotiated(&self, neg_info: &Arc<ConnectionInfo>) -> crate::Result<()> {
        {
            let config = self.config.read().await;
            if config.negotiated {
                return Err(crate::Error::InvalidState(
                    "Connection is already negotiated!".into(),
                ));
            }
        }

        let mut config = self.config.write().await;
        if neg_info.dialect.supports_compression() && neg_info.config.compression_enabled {
            let compress = neg_info.negotiation.compression.as_ref().map(|c| {
                let caps = Arc::new(c.clone());
                (Compressor::new(&caps), Decompressor::new(&caps))
            });
            config.compress = compress;
        }

        // Seed the connection-level preauth hash from the value the
        // negotiator built out of the Negotiate Req + Resp wire bytes.
        // From now on the wire pipeline is the sole owner: all subsequent
        // SessionSetup Req/Resp ingestion happens inside
        // `transform_outgoing` / `transform_incoming`.
        *self.preauth_hash.lock().await = neg_info.preauth_hash.clone();

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
    /// dispatched (the wire pipeline auto-ingested the plain bytes during
    /// `transform_outgoing`), and uses the value to derive the channel
    /// SigningKey.
    pub async fn snapshot_preauth_finalized(&self) -> crate::Result<Option<PreauthHashValue>> {
        let snapshot = self.preauth_hash.lock().await.clone();
        match snapshot.finish()? {
            PreauthHashState::Finished(v) => Ok(Some(v)),
            PreauthHashState::Unsupported => Ok(None),
            PreauthHashState::InProgress(_) => Err(crate::Error::InvalidState(
                "PreauthHashState::finish() returned InProgress — should be unreachable".into(),
            )),
        }
    }

    pub async fn reset_preauth_to_negotiate(&self) -> crate::Result<()> {
        let baseline = self
            .config
            .read()
            .await
            .conn_info
            .as_ref()
            .ok_or_else(|| crate::Error::InvalidState("connection is not negotiated".into()))?
            .preauth_hash
            .clone();
        *self.preauth_hash.lock().await = baseline;
        self.setup_signers.lock().await.clear();
        Ok(())
    }

    /// Cached `ConnectionInfo` captured by `negotiated`. None before
    /// negotiation completes. Used by the setup-phase signing path
    /// (S4-T3) to derive the dialect / signing algorithm without
    /// re-borrowing from the generation_runtime on every send.
    #[allow(dead_code)] // wired up in S4-T3
    async fn conn_info(&self) -> crate::Result<Option<Arc<ConnectionInfo>>> {
        Ok(self.config.read().await.conn_info.clone())
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
        Self::derive_setup_phase_signer_with_hash(session_key, preauth_snapshot, &conn_info)
    }

    fn derive_setup_phase_signer_with_hash(
        session_key: &crate::crypto::KeyToDerive,
        preauth_snapshot: Option<PreauthHashValue>,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<crate::session::MessageSigner> {
        let channel_info = crate::session::ChannelInfo::new(
            // The id only matters for in-session channel tracking; a
            // setup-phase signer is anonymous (no session table entry
            // yet), so any sentinel will do.
            u32::MAX,
            session_key,
            &preauth_snapshot,
            conn_info,
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
    pub async fn session_started(&self, session: &Arc<SessionAndChannel>) -> crate::Result<()> {
        let rconfig = self.config.read().await;
        if !rconfig.negotiated {
            return Err(crate::Error::InvalidState(
                "Connection is not negotiated yet!".to_string(),
            ));
        }

        let session_id = session.session_id;
        self.sessions
            .write()
            .await
            .insert(session_id, session.clone());

        tracing::trace!(
            "Session {} started and inserted to generation_runtime {:p}.",
            session_id,
            self
        );

        Ok(())
    }

    /// Notifies that a session has ended.
    pub async fn session_ended(&self, session: &Arc<SessionAndChannel>) -> crate::Result<()> {
        let session_id = session.session_id;
        self.sessions
            .write()
            .await
            .remove(&session_id)
            .ok_or(crate::Error::InvalidState(format!(
                "Session {session_id} not found!",
            )))?;

        tracing::trace!(
            "Session {} ended and removed from generation_runtime {:p}.",
            session_id,
            self
        );

        Ok(())
    }

    /// Looks up the [`SessionAndChannel`] entry for `session_id`.
    /// Errs with `InvalidState` when the wire pipeline has no record of
    /// that session.
    ///
    /// Internal helper for the public `get_signer` / `get_encryptor` /
    /// etc. accessors below. Each accessor extracts exactly what it
    /// needs (signer clone, encryptor clone, channel binding bit) and
    /// releases the read guard before returning — no closure-over-lock
    /// pattern remains.
    #[inline]
    async fn session_entry(&self, session_id: u64) -> crate::Result<Arc<SessionAndChannel>> {
        let sessions = self.sessions.read().await;
        sessions
            .get(&session_id)
            .cloned()
            .ok_or(crate::Error::InvalidState(format!(
                "Session {session_id} not found!",
            )))
    }

    /// Returns a fresh clone of the channel signer for `session_id`,
    /// or `Ok(None)` when the session entry exists but its channel
    /// slot hasn't been installed yet (e.g., a Negotiate Response
    /// arriving before `make_channel` finishes).
    ///
    /// Errs with `InvalidState` when no entry for `session_id` is
    /// in the wire pipeline's sessions table. Callsites map `Ok(None)`
    /// to the per-site `TransformError` they need.
    pub(crate) async fn get_signer(&self, session_id: u64) -> crate::Result<Option<MessageSigner>> {
        let entry = self.session_entry(session_id).await?;
        match entry.channel() {
            Some(channel) => Ok(Some(channel.signer()?.clone())),
            None => {
                let signers = self.setup_signers.lock().await;
                Ok(signers.get(&session_id).cloned())
            }
        }
    }

    /// `true` iff the channel for `session_id` is installed *and*
    /// flagged as a binding-only channel. Used by
    /// [`Self::is_binding_session_setup_signed`] to enable an extra
    /// defense-in-depth signature verification on SessionSetup
    /// responses that violate MS-SMB2 3.2.4.1.1 by carrying a
    /// non-zero signature without the `signed` flag (a quirk of some
    /// server implementations, notably ksmbd, during multichannel
    /// binding).
    ///
    /// Returns `Ok(false)` when the channel hasn't been installed —
    /// matches the swallow-error behaviour of the pre-refactor
    /// closure path. Errs only when `session_id` is unknown to the
    /// wire pipeline.
    pub(crate) async fn is_binding(&self, session_id: u64) -> crate::Result<bool> {
        let entry = self.session_entry(session_id).await?;
        Ok(entry
            .channel()
            .map(|channel| channel.is_binding())
            .unwrap_or(false))
    }

    /// Returns a fresh clone of the session encryptor for `session_id`,
    /// or `Ok(None)` when the session hasn't reached `Ready` yet (no
    /// encryptor derived). The clone is an `Arc`-clone of the underlying
    /// AEAD algo — see [`MessageEncryptor`] for the safety argument
    /// covering concurrent reuse.
    ///
    /// The point of returning an owned [`MessageEncryptor`] is to let
    /// callers drop the sessions read lock *before* running the AEAD
    /// encrypt, which is the most expensive single step on the outgoing
    /// hot path.
    pub(crate) async fn get_encryptor(
        &self,
        session_id: u64,
    ) -> crate::Result<Option<MessageEncryptor>> {
        let entry = self.session_entry(session_id).await?;
        entry.session.read().await.encryptor_clone()
    }

    /// Mirror of [`Self::get_encryptor`] for the incoming decrypt path.
    pub(crate) async fn get_decryptor(
        &self,
        session_id: u64,
    ) -> crate::Result<Option<MessageDecryptor>> {
        let entry = self.session_entry(session_id).await?;
        entry.session.read().await.decryptor_clone()
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
    /// - The resulting immutable [`SendFrame`] is ready for transport.
    ///
    /// **Constraints:**
    /// - No `additional_data` zero-copy bodies (data is whatever each
    ///   member's `PlainRequest` serializes to).
    /// - The runtime owner must have populated `header.message_id` and
    ///   `credit_charge` / `credit_request`; domain policy supplies tree and
    ///   session identity before this call.
    /// - Caller is responsible for setting `flags.related_operations` on the
    ///   2nd..Nth members and the `0xFF…FF` sentinel `FileId` on commands that
    ///   want to chain context from a prior Create.
    ///
    /// Returns `Err(InvalidArgument)` for an empty chain, inconsistent
    /// protection policy, or any member with `additional_data`.
    pub async fn transform_outgoing_compound(
        &self,
        mut msgs: Vec<CommandRequest>,
    ) -> crate::Result<SendFrame> {
        if msgs.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "compound chain requires at least one message".to_string(),
            ));
        }
        for (i, m) in msgs.iter().enumerate() {
            if m.additional_data.is_some() {
                return Err(crate::Error::InvalidArgument(format!(
                    "compound member {i}: additional_data is not supported in compound mode",
                )));
            }
        }

        let mut builder = WireBuilder::encode(msgs.iter_mut().map(|msg| &mut msg.message), 1)?;
        builder.finalize_offsets()?;

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
        let should_encrypt = matches!(msgs[0].security, Some(Protection::Encrypt));
        if msgs
            .iter()
            .any(|message| matches!(message.security, Some(Protection::Encrypt)) != should_encrypt)
        {
            return Err(crate::Error::InvalidArgument(
                "compound chain has inconsistent encryption policy".to_string(),
            ));
        }
        let should_sign = !should_encrypt && msgs[0].message.header.flags.signed();
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
                .get_signer(session_id)
                .await?
                .ok_or(crate::Error::TranformFailed(TransformError {
                    outgoing: true,
                    phase: TransformPhase::SignVerify,
                    session_id: Some(session_id),
                    why: "Compound message is signed, but no channel signer is set up",
                    msg_id: None,
                }))?;

            for (i, msg) in msgs.iter_mut().enumerate() {
                let mut signer = signer.clone();
                let signature = signer.signature_for_segments(
                    &mut msg.message.header,
                    builder.signing_segments(i)?,
                )?;
                msg.message.header.signature = signature;
                builder.patch_signature(i, signature)?;
                tracing::trace!(
                    "Compound member {i} (msg_id {}) signed (signature={}).",
                    msg.message.header.message_id,
                    msg.message.header.signature,
                );
            }
            builder.finish_signed()?;
        } else {
            builder.finish_unsigned()?;
        }

        let session_id = msgs[0].message.header.session_id;
        self.protect_wire(builder.seal()?, should_encrypt, session_id)
            .await
    }

    /// Transforms an outgoing message to a raw SMB message.
    pub async fn transform_outgoing(&self, mut msg: CommandRequest) -> crate::Result<SendFrame> {
        // Single source of truth for what to do with this message: the
        // sealed `Protection` enum. Callers that haven't been migrated
        // off the legacy `encrypt: bool` / `flags.signed()` hint fields
        // fall through to a compatibility branch that mirrors the old
        // behaviour — most of those callers (Negotiate Request) want
        // no protection at all.
        let (should_sign, should_encrypt) = match &msg.security {
            Some(Protection::None) => (false, false),
            Some(Protection::SignWithChannel) | Some(Protection::SnapshotKdfSign { .. }) => {
                (true, false)
            }
            Some(Protection::Encrypt) => (false, true),
            None => (msg.message.header.flags.signed(), false),
        };
        let session_id = msg.message.header.session_id;

        let mut builder = WireBuilder::encode(std::iter::once(&mut msg.message), usize::MAX)?;
        if let Some(data) = msg.additional_data.take() {
            builder.attach_payload(data)?;
        }
        builder.finalize_offsets()?;

        // Per MS-SMB2 §3.1.4.2, Negotiate Requests and *all*
        // SessionSetup Requests participate in the connection-level
        // preauth integrity hash. We ingest the plain (signature=0)
        // bytes here so the hash is identical to what the server
        // computes on receive. Doing it inside the wire pipeline
        // centralises the contract: the session-setup driver doesn't
        // need to know which messages count.
        if Self::participates_in_preauth_outgoing(&msg.message.header)
            && !(msg.message.header.command == Command::SessionSetup
                && msg.message.header.flags.signed())
        {
            if let Some(plain) = builder.signing_segments(0)?.next() {
                let mut hash = self.preauth_hash.lock().await;
                // Clone-then-replace: if `next` errors we want to keep
                // the previous hash state intact, not corrupt it to a
                // default `Unsupported`.
                *hash = hash.clone().next(plain)?;
            }
        }

        // 1. Sign
        let mut setup_session_key = None;
        if should_sign {
            debug_assert!(
                !should_encrypt,
                "Should not sign and encrypt at the same time!"
            );

            let mut signer =
                if let Some(Protection::SnapshotKdfSign { session_key }) = msg.security.take() {
                    setup_session_key = Some(session_key);
                    // Setup-phase path: the final SessionSetup Request signs
                    // itself with a one-shot key derived from the pre-final
                    // request hash. After signing, the exact wire request is
                    // added to the transcript and a response signer is
                    // derived from that updated hash.
                    self.derive_setup_phase_signer(&session_key).await?
                } else {
                    self.get_signer(session_id)
                        .await?
                        .ok_or(crate::Error::TranformFailed(TransformError {
                            outgoing: true,
                            phase: TransformPhase::SignVerify,
                            session_id: Some(session_id),
                            why: "Message is required to be signed, but no channel is set up!",
                            msg_id: Some(msg.message.header.message_id),
                        }))?
                };

            let signature = signer
                .signature_for_segments(&mut msg.message.header, builder.signing_segments(0)?)?;
            msg.message.header.signature = signature;
            builder.patch_signature(0, signature)?;
            builder.finish_signed()?;

            tracing::debug!(
                "Message #{} signed (signature={}).",
                msg.message.header.message_id,
                msg.message.header.signature
            );
        } else {
            builder.finish_unsigned()?;
        }

        let wire = builder.seal()?;

        if let Some(session_key) = setup_session_key {
            if let Some(signed_request) = wire.segments().next() {
                let mut hash = self.preauth_hash.lock().await;
                *hash = hash.clone().next(signed_request)?;
            }
            let response_signer = self.derive_setup_phase_signer(&session_key).await?;
            self.setup_signers
                .lock()
                .await
                .insert(session_id, response_signer);
        }

        self.protect_wire(wire, should_encrypt, session_id).await
    }

    /// Consume one sealed plain wire owner and return the sole immutable frame
    /// handed to the backend. Ordinary and compound messages must share this
    /// protection order so transform composition cannot diverge again.
    async fn protect_wire(
        &self,
        wire: smb_msg::WireMessage,
        should_encrypt: bool,
        session_id: u64,
    ) -> crate::Result<SendFrame> {
        const COMPRESSION_THRESHOLD: usize = 1024;
        let compressor = if wire.total_len() > COMPRESSION_THRESHOLD {
            self.config
                .read()
                .await
                .compress
                .as_ref()
                .map(|pair| pair.0.clone())
        } else {
            None
        };

        let encryptor = if should_encrypt {
            Some(
                self.get_encryptor(session_id)
                    .await?
                    .ok_or(crate::Error::TranformFailed(TransformError {
                        outgoing: true,
                        phase: TransformPhase::EncryptDecrypt,
                        session_id: Some(session_id),
                        why: "Message is required to be encrypted, but no encryptor is set up!",
                        msg_id: None,
                    }))?,
            )
        } else {
            None
        };

        Self::protect_wire_with(wire, compressor, encryptor, session_id)
    }

    fn protect_wire_with(
        wire: smb_msg::WireMessage,
        compressor: Option<Compressor>,
        encryptor: Option<MessageEncryptor>,
        session_id: u64,
    ) -> crate::Result<SendFrame> {
        let should_encrypt = encryptor.is_some();

        if compressor.is_none() && !should_encrypt {
            return SendFrame::from_segments(wire.into_segments(), usize::MAX).map_err(Into::into);
        }

        let encryption_prefix = if should_encrypt {
            EncryptedHeader::STRUCTURE_SIZE
        } else {
            0
        };

        // Compression consumes the plain owner. Its serialized output is
        // written directly after any reserved encryption header, avoiding a
        // second transformed frame owner.
        let mut transformed = if let Some(compressor) = compressor {
            let plain = wire.into_contiguous(0)?;
            compressor.compress_transform(&plain, encryption_prefix)?
        } else {
            wire.into_contiguous(encryption_prefix)?
        };

        if let Some(encryptor) = encryptor {
            let encrypted_header = encryptor.encrypt_message(
                &mut transformed[EncryptedHeader::STRUCTURE_SIZE..],
                session_id,
            )?;
            encrypted_header.write(&mut Cursor::new(
                &mut transformed[..EncryptedHeader::STRUCTURE_SIZE],
            ))?;
        }

        let transformed = smb_msg::TransformFrame::from_vec(transformed)?;
        SendFrame::from_segments(vec![transformed.into_bytes()], 1).map_err(Into::into)
    }

    /// Transforms an incoming message buffer to one or more [`CommandResponse`]s,
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
    pub async fn transform_incoming_all(&self, data: Bytes) -> crate::Result<Vec<CommandResponse>> {
        let (message, data) = Response::decode_frame(data)?.into_parts();
        let mut form = MessageForm::default();

        // 1. Decrypt (whole chain)
        let (message, raw) = if let Response::Encrypted(encrypted_message) = message {
            let session_id = encrypted_message.header.session_id;
            form.encrypted = true;
            let decryptor =
                self.get_decryptor(session_id)
                    .await?
                    .ok_or(crate::Error::TranformFailed(TransformError {
                        outgoing: false,
                        phase: TransformPhase::EncryptDecrypt,
                        session_id: Some(session_id),
                        why: "Message is required to be encrypted, but no decryptor is set up!",
                        msg_id: None,
                    }))?;
            let (msg, vec) = decryptor.decrypt_message(encrypted_message)?;
            (msg, Bytes::from(vec))
        } else {
            (message, data)
        };

        // 2. Decompress (whole chain)
        debug_assert!(!matches!(message, Response::Encrypted(_)));
        let (message, raw) = if let Response::Compressed(compressed_message) = message {
            let rconfig = self.config.read().await;
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
        let mut out: Vec<CommandResponse> = Vec::new();
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
            if Self::participates_in_preauth_incoming(&current.header) {
                let mut hash = self.preauth_hash.lock().await;
                *hash = hash.clone().next(&this_slice)?;
            }
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
            out.push(CommandResponse::new(current, this_slice, member_form));

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

    /// (Internal)
    ///
    /// A helper method to verify the incoming message.
    /// This method is used to verify the signature of the incoming message,
    /// if such verification is required.
    async fn verify_plain_incoming(
        &self,
        message: &mut PlainResponse,
        raw: &[u8],
        form: &mut MessageForm,
    ) -> crate::Result<()> {
        // A server cannot sign a session-invalidated response with a key it has
        // already discarded. Treat these two statuses only as unauthenticated
        // recovery signals; their payload is never consumed as business data.
        if matches!(
            message.header.status,
            value if value == Status::UserSessionDeleted as u32
                || value == Status::NetworkSessionExpired as u32
        ) {
            form.unauthenticated_recovery_hint = true;
            return Ok(());
        }
        // Check if signing check is required.
        if form.encrypted
            || message.header.message_id == u64::MAX
            || message.header.status == Status::Pending as u32
            || !(message.header.flags.signed()
                || self.is_binding_session_setup_signed(message).await)
        {
            return Ok(());
        }

        // Verify signature (if required, according to the spec)
        let session_id = message.header.session_id;
        let mut signer = self
            .get_signer(session_id)
            .await?
            .ok_or(crate::Error::TranformFailed(TransformError {
                outgoing: false,
                phase: TransformPhase::SignVerify,
                session_id: Some(session_id),
                why: "Message is required to be signed, but no channel is set up!",
                msg_id: Some(message.header.message_id),
            }))?;

        signer.verify_signature(&mut message.header, raw)?;
        if message.header.command == Command::SessionSetup
            && message.header.status == Status::Success as u32
        {
            self.setup_signers.lock().await.remove(&session_id);
        }
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
    /// Defense-in-depth signature check for multichannel binding.
    ///
    /// MS-SMB2 3.2.4.1.1 mandates:
    /// > "If the client signs the request, it MUST set the SMB2_FLAGS_SIGNED
    /// > bit in the Flags field of the SMB2 header."
    ///
    /// Some server implementations (notably ksmbd) emit SessionSetup
    /// responses *during multichannel binding* that violate this:
    /// the `signed` flag is cleared but the signature field is
    /// non-zero. The wire-spec default would silently skip
    /// verification (because the flag is what marks a message as
    /// "claims to be signed"), letting a corrupted signature go
    /// undetected.
    ///
    /// When this returns `true`, [`Self::verify_plain_incoming`]
    /// promotes the response to a verified-signature path anyway,
    /// running full crypto verification against the bytes. If the
    /// signature is genuine the response is accepted; if not it is
    /// rejected.
    ///
    /// Narrow precondition: command is SessionSetup AND signature is
    /// non-zero AND the channel is in binding state (set only in
    /// `SetupKind::Bind`). Non-binding paths follow the spec verbatim.
    async fn is_binding_session_setup_signed(&self, message: &PlainResponse) -> bool {
        if message.header.command != Command::SessionSetup || message.header.signature == 0 {
            return false;
        }
        let session_id = message.header.session_id;
        self.is_binding(session_id).await.unwrap_or(false)
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

#[cfg(test)]
mod wire_builder_tests {
    use super::*;

    #[tokio::test]
    async fn plain_bytes_write_keeps_payload_identity_through_sealed_frame() {
        let payload = Bytes::from_static(b"identity-preserved");
        let pointer = payload.as_ptr();
        let outgoing = CommandRequest::new(
            WriteRequest::new(0, FileId::EMPTY, WriteFlags::new(), payload.len() as u32).into(),
        )
        .with_additional_data(payload);

        let wire = WirePipeline::default()
            .transform_outgoing(outgoing)
            .await
            .unwrap();

        assert_eq!(wire.segments().len(), 2);
        assert_eq!(wire.segments()[1].as_ptr(), pointer);
    }

    #[tokio::test]
    async fn unsigned_session_loss_is_marked_only_as_a_recovery_hint() {
        let mut response = PlainResponse::new(ResponseContent::Logoff(LogoffResponse {}));
        response.header.status = Status::UserSessionDeleted as u32;
        response.header.credit_request = 64;
        response.header.flags.set_server_to_redir(true);
        response.header.flags.set_signed(true);
        response.header.signature = 0xfeed;
        let mut form = MessageForm::default();

        WirePipeline::default()
            .verify_plain_incoming(&mut response, &[0; 64], &mut form)
            .await
            .unwrap();

        assert!(form.unauthenticated_recovery_hint);
        assert!(!form.signed_or_encrypted());
    }

    #[test]
    #[cfg(feature = "encrypt_aes128gcm")]
    fn encrypted_compound_uses_one_transform_owner_and_preserves_chain() {
        let session_id = 7;
        let mut requests = [
            PlainRequest::new(LogoffRequest {}.into()),
            PlainRequest::new(LogoffRequest {}.into()),
            PlainRequest::new(LogoffRequest {}.into()),
        ];
        for (index, request) in requests.iter_mut().enumerate() {
            request.header.session_id = session_id;
            request.header.message_id = index as u64;
        }
        let mut builder = WireBuilder::encode(&mut requests, 1).unwrap();
        builder.finalize_offsets().unwrap();
        builder.finish_unsigned().unwrap();

        let key = [0x42; 16];
        let encryptor = MessageEncryptor::new(
            crate::crypto::make_encrypting_algo(EncryptionCipher::Aes128Gcm, &key).unwrap(),
        );
        let frame = WirePipeline::protect_wire_with(
            builder.seal().unwrap(),
            None,
            Some(encryptor),
            session_id,
        )
        .unwrap();
        assert_eq!(frame.segments().len(), 1);

        let mut cursor = Cursor::new(frame.segments()[0].as_ref());
        let encrypted_header = EncryptedHeader::read_le(&mut cursor).unwrap();
        let mut encrypted_payload = frame.segments()[0][cursor.position() as usize..].to_vec();
        let decryptor =
            crate::crypto::make_encrypting_algo(EncryptionCipher::Aes128Gcm, &key).unwrap();
        decryptor
            .decrypt(
                &mut encrypted_payload,
                &encrypted_header.aead_bytes(),
                &encrypted_header.nonce,
                encrypted_header.signature,
            )
            .unwrap();

        let mut offset = 0;
        for index in 0..3 {
            let header = Header::read(&mut Cursor::new(&encrypted_payload[offset..])).unwrap();
            assert_eq!(header.message_id, index as u64);
            if index < 2 {
                assert!(header.next_command > 0);
                assert_eq!(header.next_command % 8, 0);
                offset += header.next_command as usize;
            } else {
                assert_eq!(header.next_command, 0);
            }
        }
    }

    #[test]
    #[cfg(all(feature = "encrypt_aes128gcm", feature = "compress_lz4"))]
    fn compression_is_serialized_inside_the_final_encrypted_owner() {
        let session_id = 11;
        let payload = Bytes::from(vec![0x5a; 4096]);
        let mut request = PlainRequest::new(
            WriteRequest::new(0, FileId::EMPTY, WriteFlags::new(), payload.len() as u32).into(),
        );
        request.header.session_id = session_id;
        let mut builder = WireBuilder::encode(std::iter::once(&mut request), 2).unwrap();
        builder.attach_payload(payload).unwrap();
        builder.finalize_offsets().unwrap();
        builder.finish_unsigned().unwrap();
        let wire = builder.seal().unwrap();
        let original_size = wire.total_len();

        let caps = Arc::new(CompressionCapabilities {
            flags: CompressionCapsFlags::new(),
            compression_algorithms: vec![CompressionAlgorithm::LZ4],
        });
        let key = [0x24; 16];
        let frame = WirePipeline::protect_wire_with(
            wire,
            Some(Compressor::new(&caps)),
            Some(MessageEncryptor::new(
                crate::crypto::make_encrypting_algo(EncryptionCipher::Aes128Gcm, &key).unwrap(),
            )),
            session_id,
        )
        .unwrap();

        let mut cursor = Cursor::new(frame.segments()[0].as_ref());
        let header = EncryptedHeader::read_le(&mut cursor).unwrap();
        let mut payload = frame.segments()[0][cursor.position() as usize..].to_vec();
        crate::crypto::make_encrypting_algo(EncryptionCipher::Aes128Gcm, &key)
            .unwrap()
            .decrypt(
                &mut payload,
                &header.aead_bytes(),
                &header.nonce,
                header.signature,
            )
            .unwrap();

        assert_eq!(&payload[..4], b"\xfcSMB");
        assert_eq!(
            u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize,
            original_size,
        );
    }
}
