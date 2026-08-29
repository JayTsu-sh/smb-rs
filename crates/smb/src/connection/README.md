# Connection runtime

Each physical connection generation is owned by one asynchronous runtime task.
The owner is the only authority for admission, MessageId allocation, credits,
pending operations, deadlines, cancellation, and terminal publication.

The owner creates exactly two transport tasks: one read pump and one write
pump. Domain-facing code submits typed operations through `RuntimeHandle` and
never owns transport halves or pending-response registries.

`RuntimeWorker` is a temporary outer-shape facade for callers that still use
separate send and receive methods. It contains no request authority and is
removed when those callers move directly to typed operations.
