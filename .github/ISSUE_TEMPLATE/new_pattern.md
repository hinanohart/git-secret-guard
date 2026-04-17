---
name: New pattern proposal
about: Propose a new credential shape for the catalog.
title: "[pattern] "
labels: enhancement
---

## Proposed ID

<!-- kebab-case, <category>-<short-name>, e.g. stripe-restricted-key -->

## Severity

<!-- BLOCK (strong signal of a live credential) or WARN (plausibly a credential
     but also plausibly a test fixture / documented example). -->

## Service

<!-- The concrete service this token authenticates against. "Might be a
     credential" isn't good enough; there must be a named system. -->

## Source

<!-- Link to the vendor documentation that defines the token shape.
     Rotation / format-change advisories are especially useful. -->

## Proposed regex

```regex

```

## Positive cases

<!-- Dummy tokens with the right prefix + random chars. NEVER paste a
     real credential, even one you've rotated. -->

- `...`

## Negative cases

<!-- Strings that look similar but MUST NOT fire. Think: test fixtures,
     docs snippets, variable names that contain the substring. -->

- `...`

## Trade-offs considered

<!-- Why is this shape tight enough not to cry wolf? What legitimate
     uses exist, and are they rare enough to justify the rule? -->
