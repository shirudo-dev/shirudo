# CBMC proofs

The two C harnesses left in `testing/proofs/cbmc/` cover the pin-name
functions still implemented in C. `proofs.list` gives each harness its
unwind bound. `proof-coverage.rst` states the property and input bound.

## Change a harness

1. Read the C function and the existing harness. State the observable
   contract, not the steps the function takes.
2. Put symbolic inputs within the documented bound. Use
   `__CPROVER_assume()` for preconditions and `__CPROVER_assert()` for
   each claim. Include `proof.h` and the C file under test.
3. Run `make proofs-cbmc PROOFS=<name>`. For a failure, use
   `testing/proofs/cbmc/run.sh -v <name>` to read the input and trace.
4. Break the property deliberately, check that the proof fails, then
   restore the code. Update the coverage row with any changed bound.

CBMC checks memory accesses and arithmetic as well as the harness's
claims. A fixed bound is part of the claim: an unwinding assertion that
fails means the proof does not hold at that bound. Keep the harness on
production C. A copied test helper would prove only itself.

## When a proof is slow or fails

A symbolic length makes every access to an array costly. Run separate
fixed lengths when they cover the same set of inputs. Give each loop an
unwind bound large enough for those lengths; never disable the
unwinding assertion. A failed assertion can mean a real bug, a wrong
contract or a missing precondition. Reproduce its concrete input in a
unit test before deciding which.

`run.sh` uses CBMC 5.95.1 with unsigned `char`, as the build does. It
rejects calls without a body. Model an external call only when its
outcomes are needed for the property; state what the model leaves out
in the coverage page. A bug found by a proof gets its own fix commit.
