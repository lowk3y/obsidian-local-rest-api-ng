# How can I contribute?

Thanks for your interest in contributing to **Local REST API NG**! This is a security-hardened fork of [coddingtonbear/obsidian-local-rest-api](https://github.com/coddingtonbear/obsidian-local-rest-api). Contributions are welcome, but a bit of coordination up front goes a long way toward ensuring everyone's time is well spent.

## Start with an Issue or Discussion

Before opening a pull request — especially for **new features or behavioral changes** — please open an issue first:

[https://github.com/lowk3y/obsidian-local-rest-api-ng/issues](https://github.com/lowk3y/obsidian-local-rest-api-ng/issues)

This helps confirm that the idea aligns with the project's direction and avoids contributors investing time in changes that ultimately won't be merged.

> **Note:** For contributions to the **original upstream project**, see [coddingtonbear/obsidian-local-rest-api](https://github.com/coddingtonbear/obsidian-local-rest-api). This fork focuses specifically on the security filtering layer, audit logging, and access control features.

## Scope of This Fork

This project adds a security filter layer on top of the upstream REST API. Contributions in the following areas are especially welcome:

- **Security filtering** — folder, name, tag, and keyword filters
- **Access control** — rule evaluation, default-deny policy, per-method filtering
- **Audit logging** — access logs, error logs, log formats
- **Read-only mode** — write-blocking behavior
- **Path normalization** — traversal guards, input sanitization
- **Testing** — unit tests, integration tests, MCP test cases

For changes to **core API endpoints** (vault CRUD, search, commands, periodic notes), consider whether the change belongs upstream in the original project instead.

## Getting Started

### Prerequisites

- Node.js >= 16
- npm

### Setup

```bash
git clone https://github.com/lowk3y/obsidian-local-rest-api-ng.git
cd obsidian-local-rest-api-ng
npm install
npm run build
```

### Run Tests

```bash
npm test
```

All tests must pass before submitting a PR. The test suite covers:

| Module | Tests |
|--------|-------|
| `folder-filter` | 14 |
| `document-name-filter` | 7 |
| `rules-file` | 25 |
| `filter-engine` | 20 |
| `requestHandler` | 62 |

## Contribution Expectations

### API Design

- Any new APIs **must be REST-ful**, or as REST-ful as is reasonably achievable given constraints.
- Consistency with existing API patterns is strongly preferred.
- Backward-incompatible changes are **discouraged**; if a breaking change is proposed, it should be clearly justified and discussed in advance.

### Security Considerations

Since this project is specifically about security:

- New filter types or rule syntax changes should fail closed (deny on error).
- Path handling must go through normalization — no raw user input in file operations.
- Test both allow and deny cases for any filter changes.
- Consider edge cases: empty paths, special characters, Unicode, path traversal.

### Tests & Documentation

All contributions that modify behavior or add features are expected to:

- Update or add tests covering the new behavior
- Update documentation to describe the change or new functionality

Changes without corresponding tests or documentation are unlikely to be accepted.

### Scope & Quality

- Pull requests should remain **narrowly scoped** to the problem they intend to solve.
- Unrelated refactors, cleanup, or stylistic changes should be avoided unless discussed beforehand.
- CI failures or linting issues should be resolved before review.

### Ownership & Follow-Through

- Contributors are expected to **actively shepherd their pull requests**, including responding to feedback and making requested changes.
- Pull requests that see **no forward progress for 90 days** may be closed due to inactivity.

## Communication & Conduct

- Please communicate respectfully and patiently.
- Questions, suggestions, and constructive disagreement are welcome — but entitlement or pressure is not.

## Credits

This project is built on the excellent work of [Adam Coddington](https://coddingtonbear.net/) and the [obsidian-local-rest-api](https://github.com/coddingtonbear/obsidian-local-rest-api) project. We're grateful for the foundation that makes this security extension possible.
