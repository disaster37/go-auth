# ADR-001: Framework-agnostic architecture

## Status

Accepted.

## Context

The authentication code in `dagger-kubernetes` is built on CloudWeGo Hertz,
while `gohookbridge` uses `net/http` with `chi`. Sharing logic directly would
force one framework on the other and pull router dependencies into every
consumer.

## Decision

- Core packages (`domain`, `crypto`, `store`, `password`, `jwt`, `apitoken`,
  `oauth`, `httpcookie`, `secguard`, `observ`, `config`) import no HTTP
  framework.
- Shared entities and sentinel errors live in `domain` (stdlib only). The root
  `goauth` package re-exports them and provides the turnkey `Service` facade.
- `nethttp` is an optional adapter built only on the standard library.
- Framework-specific integrations (for example Hertz) are documented recipes
  that compose the core primitives.

## Consequences

- Consumers keep their existing routers and middleware stacks.
- The dependency graph stays acyclic: `handler → service → domain ← repository`.
- Framework adapters are small and independently testable.
- Some glue code (cookie writing, error mapping) is duplicated per framework,
  but it is intentionally thin and documented.
