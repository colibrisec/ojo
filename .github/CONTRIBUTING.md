# Contributing to ojo

Thanks for helping make ojo a more useful open-source security scanner. Contributions to code, scanner rules, documentation, tests, and bug reports are welcome.

## Before you start

- Search existing [issues](https://github.com/colibrisec/ojo/issues) before opening a new one.
- For substantial changes, open an issue first so the approach can be discussed before implementation.
- Do not report security vulnerabilities in public issues. Follow the repository's security-reporting guidance instead.

## Development setup

Requires Go 1.26.5 or later.

```console
git clone https://github.com/colibrisec/ojo.git
cd ojo
go test ./...
go build ./...
```

To build the documentation locally:

```console
pip install -r docs-requirements.txt
mkdocs serve
```

## Making a change

1. Create a focused branch from `main`.
2. Keep changes small and limited to one purpose.
3. Add or update tests for changed behavior.
4. Update documentation when user-visible behavior, scanner coverage, configuration, or CLI output changes.
5. Run the checks below before opening a pull request.

```console
go vet ./...
go test ./...
go build ./...
mkdocs build --strict
```

## Pull requests

- Explain what changed and why it matters.
- Link the related issue when one exists.
- Include tests that demonstrate the intended behavior and regressions being prevented.
- Keep generated files, unrelated formatting changes, and secrets out of the pull request.
- Ensure all CI checks pass before requesting review.

## Scanner rules

Detection rules should prioritize clear, actionable findings. Include positive and negative test cases, avoid reporting placeholder values or test fixtures as real secrets, and document any new rule identifiers, severity choices, or configuration.

## Code of conduct

Be respectful, constructive, and professional. Harassment and abusive behavior are not welcome.
