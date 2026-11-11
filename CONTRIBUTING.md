# Contributing

Thanks for contributing to `github.com/disaster37/go-auth`.

## Development workflow

1. Fork the repository and create a topic branch from `main`.
2. Make focused changes with tests.
3. Run the full verification suite locally:

   ```bash
   gofmt -s -l .
   goimports -l -local github.com/disaster37/go-auth .
   go build ./...
   go vet ./...
   go test -race -covermode=atomic -timeout 180s ./...
   golangci-lint run
   ```

4. Run the Dagger CI gate when Docker is available:

   ```bash
   dagger call -m ./dagger --src . ci export --path out
   ```

5. Open a pull request describing the change and its motivation.

## Coding conventions

- Use `fmt.Sprintf` for dynamic strings; never concatenate with `+`.
- Wrap errors with `%w` so callers can use `errors.Is`/`errors.As`.
- Use the standard library `testing` package only (no testify or ginkgo).
- Prefer table-driven tests.
- Keep the public API additive unless a breaking change is explicitly approved.
- Run `gofmt` and `goimports` with the local prefix
  `github.com/disaster37/go-auth`.
- Do not leave dead or unused symbols; `golangci-lint` runs the `unused` linter.
- Never log or commit secrets, tokens, passwords, or private keys.

## Coverage

The CI gate requires at least 90% overall statement coverage and at least 95%
for `crypto`, `password`, `jwt`, `apitoken`, `httpcookie`, and `secguard`.

## Documentation

Update `README.md`, `docs/configuration.md`, `docs/api.md`, and the relevant ADR
when a change introduces, modifies, or removes a feature, configuration key, or
architectural decision. `docs/api.md` is generated with `gomarkdoc`.
