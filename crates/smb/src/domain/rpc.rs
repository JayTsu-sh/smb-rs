use bytes::Bytes;
use smb_rpc::{
    SmbRpcError,
    interface::{BoundRpcConnection, RpcInterface},
    ndr64::NDR64_SYNTAX_ID,
    pdu::{
        BIND_TIME_NEGOTIATION, BIND_TIME_NEGOTIATION_PREFIX, DcRpcCoPktBind, DcRpcCoPktBindAck,
        DcRpcCoPktBindContextElement, DcRpcCoPktRequest, DcRpcCoPktRequestContent,
        DcRpcCoPktResponseContent, DceRpcCoPktBindAckDefResult, DceRpcCoPktFlags,
        DceRpcCoRequestPkt, DceRpcCoResponsePkt, DceRpcSyntaxId,
    },
};

use super::{Operation, Pipe, ReplayPolicy, operation::OperationContext};
use crate::Error;

/// Bound DCE/RPC connection carried by one domain Pipe.
///
/// RPC framing, context selection, call identifiers, and fragment limits stay
/// inside this module. Callers interact through their typed `smb-rpc`
/// interface and never receive the underlying SMB Resource identity.
pub struct RpcPipeConnection {
    pipe: Pipe,
    next_call_id: u32,
    context_id: u16,
    server_max_xmit_frag: u16,
}

impl Pipe {
    /// Lazily bind this Pipe to a typed RPC interface.
    pub fn bind_rpc<I>(self) -> Operation<'static, I>
    where
        I: RpcInterface<RpcPipeConnection> + Send + 'static,
    {
        Operation::new(move |context| {
            Box::pin(async move {
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "RPC bind permits only ReplayPolicy::Never".into(),
                    ));
                }
                RpcPipeConnection::bind::<I>(self, &context).await
            })
        })
    }
}

impl RpcPipeConnection {
    const PACKED_DREP: u32 = 0x10;
    const START_CALL_ID: u32 = 2;
    const DEFAULT_FRAGMENT_LIMIT: u16 = 4280;

    async fn bind<I>(pipe: Pipe, context: &OperationContext) -> crate::Result<I>
    where
        I: RpcInterface<Self>,
    {
        let transfer_syntaxes = [NDR64_SYNTAX_ID, BIND_TIME_NEGOTIATION];
        let contexts = make_bind_contexts(I::SYNTAX_ID, &transfer_syntaxes);
        let request = DcRpcCoPktBind {
            max_xmit_frag: Self::DEFAULT_FRAGMENT_LIMIT,
            max_recv_frag: Self::DEFAULT_FRAGMENT_LIMIT,
            assoc_group_id: 0,
            context_elements: contexts,
        }
        .into();
        let reply = rpc_write_read(&pipe, Self::START_CALL_ID, request, context).await?;
        let bind_ack = match reply.content() {
            DcRpcCoPktResponseContent::BindAck(value) => value,
            DcRpcCoPktResponseContent::Fault(fault) => {
                pipe.close().await?;
                return Err(SmbRpcError::RemoteFault {
                    status: fault.status,
                }
                .into());
            }
            content => {
                return Err(Error::InvalidMessage(format!(
                    "expected RPC BindAck, received {content:?}"
                )));
            }
        };
        let context_id = accepted_context(bind_ack, &transfer_syntaxes)?;
        let server_max_xmit_frag = bind_ack.max_xmit_frag;
        Ok(I::new(Self {
            pipe,
            next_call_id: Self::START_CALL_ID + 1,
            context_id,
            server_max_xmit_frag,
        }))
    }

    /// Close the owned domain Pipe after the typed RPC client is no longer in
    /// use. Typed RPC interfaces normally own this value internally.
    pub async fn close(&self) -> crate::Result<()> {
        self.pipe.close().await.map(|_| ())
    }
}

fn make_bind_contexts(
    syntax_id: DceRpcSyntaxId,
    transfer_syntaxes: &[DceRpcSyntaxId],
) -> Vec<DcRpcCoPktBindContextElement> {
    transfer_syntaxes
        .iter()
        .enumerate()
        .map(|(index, syntax)| DcRpcCoPktBindContextElement {
            context_id: index as u16,
            abstract_syntax: syntax_id.clone(),
            transfer_syntaxes: vec![syntax.clone()],
        })
        .collect()
}

fn accepted_context(
    bind_ack: &DcRpcCoPktBindAck,
    transfer_syntaxes: &[DceRpcSyntaxId],
) -> crate::Result<u16> {
    if bind_ack.results.len() != transfer_syntaxes.len() {
        return Err(Error::InvalidMessage(format!(
            "RPC BindAck returned {} results for {} transfer syntaxes",
            bind_ack.results.len(),
            transfer_syntaxes.len()
        )));
    }
    let mut selected = None;
    for (index, (result, syntax)) in bind_ack.results.iter().zip(transfer_syntaxes).enumerate() {
        if syntax
            .uuid
            .to_string()
            .starts_with(BIND_TIME_NEGOTIATION_PREFIX)
        {
            continue;
        }
        if result.result != DceRpcCoPktBindAckDefResult::Acceptance || &result.syntax != syntax {
            return Err(Error::InvalidMessage(format!(
                "RPC transfer syntax {syntax} was not accepted exactly"
            )));
        }
        selected = Some(index as u16);
    }
    selected.ok_or_else(|| Error::InvalidMessage("RPC BindAck accepted no context".into()))
}

async fn rpc_write_read(
    pipe: &Pipe,
    call_id: u32,
    content: DcRpcCoPktRequestContent,
    context: &OperationContext,
) -> crate::Result<DceRpcCoResponsePkt> {
    let request: Vec<u8> = DceRpcCoRequestPkt::new(
        content,
        call_id,
        DceRpcCoPktFlags::new()
            .with_first_frag(true)
            .with_last_frag(true),
        RpcPipeConnection::PACKED_DREP,
    )
    .try_into()?;
    let expected = request.len();
    let mut write = pipe
        .write(Bytes::from(request))
        .cancellation(context.cancellation.clone());
    let mut read = pipe
        .read(RpcPipeConnection::DEFAULT_FRAGMENT_LIMIT.into())
        .cancellation(context.cancellation.clone());
    if let Some(remaining) = context.remaining()? {
        write = write.timeout(remaining);
        read = read.timeout(remaining);
    }
    if write.await? != expected {
        return Err(Error::InvalidMessage(
            "RPC bind request was only partially written".into(),
        ));
    }
    let reply = DceRpcCoResponsePkt::try_from(read.await?.as_ref())?;
    validate_envelope(&reply).map_err(Error::InvalidMessage)?;
    Ok(reply)
}

fn validate_envelope(reply: &DceRpcCoResponsePkt) -> Result<(), String> {
    if reply.packed_drep() != RpcPipeConnection::PACKED_DREP {
        return Err(format!(
            "unsupported RPC packed DREP {}",
            reply.packed_drep()
        ));
    }
    if !reply.pfc_flags().first_frag() || !reply.pfc_flags().last_frag() {
        return Err("fragmented RPC responses are not supported".into());
    }
    Ok(())
}

impl BoundRpcConnection for RpcPipeConnection {
    async fn send_receive_raw(
        &mut self,
        opnum: u16,
        stub_input: &[u8],
    ) -> Result<Vec<u8>, SmbRpcError> {
        let request = DcRpcCoPktRequest {
            alloc_hint: DcRpcCoPktRequest::ALLOC_HINT_NONE,
            context_id: self.context_id,
            opnum,
            stub_data: stub_input.to_vec(),
        }
        .into();
        let request: Vec<u8> = DceRpcCoRequestPkt::new(
            request,
            self.next_call_id,
            DceRpcCoPktFlags::new()
                .with_first_frag(true)
                .with_last_frag(true),
            Self::PACKED_DREP,
        )
        .try_into()
        .map_err(|error: binrw::Error| SmbRpcError::SendReceiveError(error.to_string()))?;
        self.next_call_id = self
            .next_call_id
            .checked_add(1)
            .ok_or_else(|| SmbRpcError::SendReceiveError("RPC call identifier exhausted".into()))?;
        let reply = self
            .pipe
            .transact(Bytes::from(request), self.server_max_xmit_frag.into())
            .await
            .map_err(|error| SmbRpcError::SendReceiveError(error.to_string()))?;
        let reply = DceRpcCoResponsePkt::try_from(reply.as_ref())
            .map_err(SmbRpcError::FailedToParseRpcResponse)?;
        validate_envelope(&reply).map_err(SmbRpcError::SendReceiveError)?;
        let response = match reply.into_content() {
            DcRpcCoPktResponseContent::Response(value) => value,
            DcRpcCoPktResponseContent::Fault(fault) => {
                return Err(SmbRpcError::RemoteFault {
                    status: fault.status,
                });
            }
            content => {
                return Err(SmbRpcError::SendReceiveError(format!(
                    "expected RPC Response, received {content:?}"
                )));
            }
        };
        if response.context_id != self.context_id {
            return Err(SmbRpcError::SendReceiveError(format!(
                "RPC response context {} did not match {}",
                response.context_id, self.context_id
            )));
        }
        Ok(response.stub_data)
    }
}
