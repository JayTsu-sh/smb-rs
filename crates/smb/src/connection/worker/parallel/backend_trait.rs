use maybe_async::*;
use smb_transport::{IoVec, SmbTransport};
use std::{sync::Arc, time::Duration};

use crate::msg_handler::IncomingMessage;

use super::base::ParallelWorker;

#[maybe_async(AFIT)]
#[allow(async_fn_in_trait)] // for maybe_async.
pub trait MultiWorkerBackend {
    type SendMessage;
    type AwaitingNotifier;
    type AwaitingWaiter;
    type ChannelSender: Send + std::fmt::Debug + 'static;
    type ChannelReceiver;

    async fn start(
        transport: Box<dyn SmbTransport>,
        worker: Arc<ParallelWorker<Self>>,
        send_channel_recv: Self::ChannelReceiver,
    ) -> crate::Result<Arc<Self>>
    where
        Self: std::fmt::Debug + Sized,
        Self::AwaitingNotifier: std::fmt::Debug;
    async fn stop(&self) -> crate::Result<()>;

    fn wrap_msg_to_send(msg: IoVec) -> Self::SendMessage;
    fn make_notifier_awaiter_pair() -> (Self::AwaitingNotifier, Self::AwaitingWaiter);
    fn make_send_channel_pair() -> (Self::ChannelSender, Self::ChannelReceiver);

    /// Send a message through the channel.
    fn channel_send(sender: &Self::ChannelSender, msg: Self::SendMessage) -> crate::Result<()>;

    async fn wait_on_waiter(
        waiter: Self::AwaitingWaiter,
        timeout: Duration,
    ) -> crate::Result<IncomingMessage>;
    fn send_notify(
        tx: Self::AwaitingNotifier,
        msg: crate::Result<IncomingMessage>,
    ) -> crate::Result<()>;
}
