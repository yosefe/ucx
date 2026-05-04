# Agent Guide for `bindings`

This subtree contains language bindings over UCX.

## Layout

- `bindings/go`: Go bindings and tests. The build uses cgo and links against
  the UCX libraries from the current build tree.
- `bindings/java`: JUCX, a Java API over UCP, with native C++ wrappers under
  `bindings/java/src/main/native`.

## Go Binding Notes

- Keep Go API changes synchronized with the underlying UCP/UCS C APIs.
- Update `bindings/go/Makefile.am` when adding or removing build inputs.
- Tests live under `bindings/go/tests` and use local `replace` directives in
  `go.mod`.
- CUDA-specific Go support is guarded by the build tags and configure feature
  checks already present in `bindings/go/Makefile.am`.

Useful commands after configuring UCX with Go support:

```sh
make -C bindings/go build
make -C bindings/go test
make -C bindings/go bench
```

## Java Binding Notes

- JUCX requires Java 8 or newer, Maven, and a UCX configure step with Java
  support, for example `./configure --with-java`.
- Native wrappers are C++ and should follow the UCX C/C++ style rules.
- Keep Java-facing constants, native wrappers, and public Java APIs in sync
  when mapping a new UCP/UCS feature.
- Update `bindings/java/Makefile.am` or
  `bindings/java/src/main/native/Makefile.am` when adding files.

If binding tests cannot run because Go, Java, Maven, or optional UCX features
are unavailable, report the attempted command and missing dependency.
