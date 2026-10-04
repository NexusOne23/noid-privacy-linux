## Change

Describe the problem and the resulting behavior. Link any relevant issue.

## Validation

List the relevant tests and their results. For distro or desktop behavior,
identify the tested version and environment. See [test commands](../tests/README.md).

- [ ] Syntax, ShellCheck, API lint, mapping validation and BATS checks pass
- [ ] Changed behavior has appropriate regression coverage
- [ ] Documentation and user-visible changes are updated

## Security and compatibility

Describe any changed permissions, network requests, state writes or output
semantics. Missing or failed queries must not become clean results. New network
requests must respect `--offline`; state changes must remain explicit opt-ins.
Remove private data from examples and reports, and follow the
[Code of Conduct](../CODE_OF_CONDUCT.md).
