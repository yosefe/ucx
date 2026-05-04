# Agent Guide for `docs`

This subtree contains human-facing documentation and style references.

## Documentation Layout

- `docs/source`: Sphinx documentation. It accepts `.rst` and `.md` sources.
- `docs/doxygen`: Doxygen configuration and API/design source material.
- `docs/CodeStyle.md`: C/C++ style rules.
- `docs/LoggingStyle.md`: logging rules.
- `docs/OptimizationStyle.md`: optimization guidance.

## Editing Docs

- Keep user documentation in `docs/source` unless changing developer style or
  Doxygen source material.
- Prefer relative links inside the repository.
- Do not commit generated output from `docs/_build`, Doxygen XML, or generated
  API pages.
- When documenting APIs, keep comments in the public headers synchronized with
  the narrative docs.
- Keep Markdown compatible with Sphinx/recommonmark when files are under
  `docs/source`.

## Verification

Useful commands:

```sh
make docs
make -C docs html
```

The docs build may require Sphinx, Doxygen, Breathe, and recommonmark. If those
dependencies are missing locally, report the missing tool rather than editing
around the build system.
