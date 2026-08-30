# Architecture wave evidence schema

## Status

Accepted machine-readable evidence contract for W1 and later implementation
waves. The Rust schema and validator live in `smb_tests::evidence`.

## Separation of states

An executed validation case has one of four statuses: `Passed`, `Failed`,
`Blocked`, or `NotApplicable`. `NotApplicable` is valid only for a declared
conditional hard gate and requires a stable reason code.

`NotYetActivated` is not a validation result. It is a planning status carrying
the owning future wave. It is valid only while the gate definition is also
NotYetActivated and its owner is later than the evidence wave. Missing,
duplicate, overdue, early, or owner-mismatched gates invalidate the evidence.

## Secret-free fields

Evidence stores only:

- schema version, wave, and hexadecimal commit identity;
- stable gate IDs, typed statuses, and stable reason codes;
- command categories and boolean results, never full command lines;
- an anonymized target ID and normalized platform version;
- cleanup booleans and retained-resource count.

Identifiers are limited to 1–64 ASCII alphanumeric, dash, underscore, or dot
characters. There are no username, password, endpoint, payload, arbitrary
error-text, or command-line fields.

## Checkpoint result

Valid evidence and an accepted checkpoint are different claims. Failed and
Blocked statuses are valid evidence but make the checkpoint fail. A checkpoint
passes only when:

- the schema has no structural violations;
- every command category passed;
- every activated hard gate Passed, except an allowed conditional
  NotApplicable gate;
- supplied cleanup evidence reports an empty inventory, unchanged pre-existing
  state, and zero retained resources.

The JSON evidence is a CI artifact. The repository retains a Markdown summary
that references only the same secret-free categories and aggregate results.
