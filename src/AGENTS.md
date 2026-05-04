# Agent Guide for `src`

This subtree contains UCX runtime code. Keep source edits aligned with the
layer boundaries below.

## Layer Boundaries

- `ucs`: shared infrastructure only. Avoid pulling protocol or transport policy
  into UCS.
- `uct`: transport-facing primitives and hardware-specific implementations.
  Keep backend-specific behavior inside the relevant transport directory.
- `ucp`: protocol, endpoint, worker, request, tag, AM, stream, RMA, rendezvous,
  and wireup logic. UCP should compose UCT capabilities rather than baking in a
  specific transport backend unless the existing code already does so.
- `ucm`: memory allocation/event interception and memory hook logic. Be careful
  with initialization order, async-signal-safety assumptions, and interactions
  with external allocators.
- `tools`: user-facing utilities. Keep command-line behavior and output stable
  unless the task explicitly changes it.

## Source Changes

- Update the local `Makefile.am` whenever adding, removing, or renaming source
  or header files.
- API headers live under directories such as `src/ucp/api`, `src/uct/api`, and
  `src/ucm/api`. Public API changes should include Doxygen comments and should
  be treated as compatibility-sensitive.
- Inline helpers normally use `.inl`; forward declarations use `_fwd.h`; type
  declarations use `_types.h`; macro definition headers use `_def.h`.
- Keep error handling local: log at the first point that determines the real
  error cause, and propagate `ucs_status_t` without duplicating logs in callers.
- Use `ucs_assert*` for internal invariants, not user-input validation.

## Performance and Concurrency

- Many paths are latency-sensitive. Avoid extra allocations, locks, atomics,
  string formatting, or logging in fast paths unless the local code already
  pays that cost.
- Check existing progress, async, callback queue, and worker locking patterns
  before changing concurrency behavior.
- Preserve memory type and device-specific handling. CUDA, ROCm, Level Zero,
  Gaudi, IB, TCP, and shared-memory paths often have feature guards in
  `configure.ac`, `config/m4`, and local `Makefile.am` files.

## Verification

Use the smallest build and test surface that covers the layer touched:

```sh
make -j8
make -C test/gtest test GTEST_FILTER='ucs_*'
make -C test/gtest test GTEST_FILTER='uct_*'
make -C test/gtest test GTEST_FILTER='ucp_*'
```

For transport-specific changes, prefer the matching gtest filter or existing
CI helper script, and report when local hardware support was unavailable.
