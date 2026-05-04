# Agent Guide for `examples`

This subtree contains small programs that demonstrate UCX APIs.

## Editing Examples

- Keep examples concise and focused on public API usage.
- Prefer existing helper code such as `ucp_util.h` and `hello_world_util.h`
  when it keeps the sample readable.
- Update `examples/Makefile.am` or `examples/cmake/CMakeLists.txt` when adding
  or removing example files.
- Avoid relying on hardware-specific transports unless the example is explicitly
  about that transport.
- Keep comments practical: explain API sequencing and non-obvious UCX behavior,
  not basic C syntax.

## Verification

Build examples as part of the normal project build after configuring UCX:

```sh
make -j8
```

For CMake examples, check the files under `examples/cmake` separately when they
are touched.
