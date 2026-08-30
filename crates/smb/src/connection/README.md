# Connection runtime

Each physical connection generation is owned by one asynchronous runtime task.
The owner is the only authority for admission, MessageId allocation, credits,
pending operations, deadlines, cancellation, and terminal publication.

The owner creates exactly two transport tasks: one read pump and one write
pump. Domain-facing code submits typed operations through `RuntimeHandle` and
never owns transport halves or pending-response registries.

Legacy wire mechanics remain behind `runtime::port`; no production caller can
submit separate send/receive pairs or obtain a worker handle.
