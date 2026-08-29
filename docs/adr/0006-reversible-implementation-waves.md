---
status: accepted
---

# Deliver the rewrite as dependency-ordered reversible waves

The architecture rewrite proceeds through seven implementation waves, W0
through W6, in dependency order. Each wave leaves an accepted checkpoint,
activates its owned acceptance gates, and can be reverted as a unit; reverting
an older wave requires first reverting dependent waves in reverse order. This
keeps the main branch usable and prevents behavior fixes, temporary dual
authority, or promises that a later wave will repair the current one.

The sequence is baseline freeze, validation infrastructure, wire data plane,
single-generation request runtime, cross-generation recovery and events,
domain-first public interface, then final cleanup and appliance acceptance.
Research may proceed in parallel, but merges may not. Temporary adapters must
name their removal wave, and no implementation wave may retain two
authoritative lifecycle or wire paths at its accepted checkpoint. The detailed
scope, tests, evidence, commit rules, and rollback contract are defined in
`docs/architecture/implementation-waves.md`.
