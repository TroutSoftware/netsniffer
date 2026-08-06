# Wrappers

The files in this folder are wrappers for the snort libraries, made to
make it more simple to create snort plugins

## Pegs

In the default snort implementation you need to keep two different
structures in perfect sync, the peg templates you define the structure
once, and the two structures are generated.

The lookups for referencing pegs are compiletime resolved, so it doesn't
carry any penalties
