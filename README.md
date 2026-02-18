# Local REST API NG for Obsidian

**Security-hardened fork of [coddingtonbear/obsidian-local-rest-api](https://github.com/coddingtonbear/obsidian-local-rest-api)** with configurable access filtering, read-only mode, and audit logging.

---

## Why This Fork?

AI tools (MCP servers, Claude, ChatGPT plugins, etc.) that connect to Obsidian's REST API get **unrestricted read/write access** to your entire vault. A misconfigured AI tool, a malicious MCP server, or a prompt-injected session can read your private notes, exfiltrate sensitive data, or modify files without restriction.

**Local REST API NG** solves this by adding a security filter layer between authentication and the route handlers. It ships with **default-deny active from install** — no file is accessible until you explicitly allow it.

### What's New Over Upstream

| Feature | Upstream | NG |
|---------|----------|----|
| Default access policy | Allow all | **Deny all** |
| Folder-based filtering | No | Yes (glob + regex) |
| Document name filtering | No | Yes (glob + regex) |
| Tag-based filtering | No | Yes (`#ai-allow` / `#ai-deny`) |
| Keyword content filtering | No | Yes (string + regex) |
| Per-method filtering | No | Yes (restrict rules to GET/PUT/POST/PATCH/DELETE) |
| Read-only mode | No | Yes (block all writes with one toggle) |
| Human-readable rules file | No | Yes (`access-rules.conf`) |
| Access log (CLF) | No | Yes (`logs/access.log` — nginx/apache compatible) |
| Error log | No | Yes (`logs/error.log` — nginx format) |
| Filter diagnostics | No | Yes (test paths in settings) |
| Path normalization | No | Yes (double-slash collapse, traversal guard) |

### What's Unchanged

All upstream functionality works exactly as before. The filter middleware is inserted after authentication and before route handlers — existing API endpoints, request/response formats, and the public plugin API are fully preserved.

---

## Architecture

### High-Level Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Obsidian Desktop App                         │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                    Local REST API NG Plugin                      │ │
│  │                                                                  │ │
│  │  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌─────────────┐ │ │
│  │  │  Express  │──▶│   Auth   │──▶│ Security │──▶│   Route     │ │ │
│  │  │  Server   │   │  Check   │   │  Filter  │   │  Handlers   │ │ │
│  │  └──────────┘   └──────────┘   └──────────┘   └─────────────┘ │ │
│  │       │                             │                │          │ │
│  │       │                             ▼                ▼          │ │
│  │       │                        ┌──────────┐   ┌──────────────┐ │ │
│  │       │                        │  Filter   │   │   Obsidian   │ │ │
│  │       │                        │  Engine   │   │   Vault API  │ │ │
│  │       │                        └──────────┘   └──────────────┘ │ │
│  │       │                             │                           │ │
│  │       ▼                             ▼                           │ │
│  │  ┌──────────┐              ┌───────────────┐                   │ │
│  │  │  Audit   │              │ access-rules  │                   │ │
│  │  │  Logger  │              │    .conf      │                   │ │
│  │  └──────────┘              └───────────────┘                   │ │
│  │       │                                                        │ │
│  │       ▼                                                        │ │
│  │  ┌──────────────┐  ┌─────────────┐                             │ │
│  │  │logs/         │  │logs/        │                             │ │
│  │  │ access.log   │  │ error.log   │                             │ │
│  │  └──────────────┘  └─────────────┘                             │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

### Request Flow

```
             HTTP Request
                  │
                  ▼
        ┌─────────────────┐
        │  Express Server  │  (HTTPS :27124 / HTTP :27123)
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │  Authentication  │  Bearer token check
        └────────┬────────┘
                 │ ✓ Authenticated
                 ▼
        ┌─────────────────┐
        │  Security Filter │  securityFilterMiddleware.ts
        │   Middleware     │
        └────────┬────────┘
                 │
        ┌────────┴────────────────────────────────┐
        │                                          │
        ▼                                          ▼
  ┌───────────┐                           ┌───────────────┐
  │  Exempt?  │──Yes──▶ PASS THROUGH      │  Read-Only    │
  │  (/, .crt,│                           │  Mode Check   │
  │  openapi) │                           └───────┬───────┘
  └───────────┘                                   │
                                         Write method + Yes
                                                  │
                                            ▼ 403 DENIED
                                                  │
                                            No ───┘
                                                  │
                                                  ▼
                                    ┌─────────────────────┐
                                    │  Path Normalization  │
                                    │  + Traversal Guard   │
                                    └──────────┬──────────┘
                                               │
                                               ▼
                                    ┌─────────────────────┐
                                    │   Filter Engine      │
                                    │   evaluateFile()     │
                                    └──────────┬──────────┘
                                               │
                                    ┌──────────┴──────────┐
                                    │                      │
                                 Allowed              Denied
                                    │                      │
                                    ▼                      ▼
                             Route Handler            403 JSON
                                    │              + Error Log
                                    ▼
                               Response
                          + Access Log Entry
```

### Filter Evaluation Pipeline

```
   File Path
      │
      ▼
┌─────────────┐     ┌─────────────┐     ┌──────────────┐     ┌───────────┐     ┌──────────────┐     ┌─────────────┐
│  Global     │────▶│   Folder    │────▶│  Document    │────▶│  Custom   │────▶│   Keyword    │────▶│   Default   │
│  Tags       │  no │   Rules     │  no │  Name Rules  │  no │  Tag      │  no │   Rules      │  no │   Policy    │
│ #ai-deny    │match│             │match│              │match│  Rules    │match│              │match│             │
│ #ai-allow   │     └──────┬──────┘     └──────┬───────┘     └─────┬────┘     └──────┬───────┘     └──────┬──────┘
└──────┬──────┘            │                   │                   │                   │                    │
       │                match               match               match               match            allow or deny
    match                  │                   │                   │                   │                    │
       │                   ▼                   ▼                   ▼                   ▼                    ▼
       ▼               ALLOW/DENY          ALLOW/DENY          ALLOW/DENY          ALLOW/DENY          ALLOW/DENY
   ALLOW/DENY
  (overrides
  all rules)
```

**Global tags are checked first** — `#ai-deny` always denies and `#ai-allow` always allows, overriding all other rules including folder and name deny rules.

**Then first match wins.** As soon as a rule matches, evaluation stops and its mode (allow/deny) is applied. If no rule matches, the default policy is used.

### Directory Listing & Search Filtering

For directory listings (`GET /vault/`) and search results (`GET /search`), a **response interceptor** post-filters the results:

```
Route Handler produces full file list
              │
              ▼
    Response Interceptor
    (attached by middleware)
              │
              ▼
    filterPaths() / filterSearchResults()
    evaluates each path against FilterEngine
              │
              ▼
    Only allowed files returned to client
```

---

## Installation

This plugin is not (yet) in the Obsidian community plugin directory. Install manually:

### From Source

```bash
git clone https://github.com/lowk3y/local-rest-api-ng.git
cd local-rest-api-ng
npm install
npm run build
```

### Deploy to Obsidian

```bash
# Copy the built artifacts to your vault's plugins directory
mkdir -p /path/to/vault/.obsidian/plugins/local-rest-api-ng
cp main.js manifest.json styles.css /path/to/vault/.obsidian/plugins/local-rest-api-ng/
```

Then in Obsidian: **Settings > Community Plugins > Enable "Local REST API NG"**

> **Note:** If you have the original `obsidian-local-rest-api` installed, disable it first. Both plugins use the same default ports.

---

## Quick Start

After enabling the plugin, **security filtering is ON by default with a deny-all policy**. Every API request to vault files returns `403 Access denied` until you add allow rules.

### 1. Get your API key

Open **Settings > Local REST API NG**. Your API key is displayed at the top.

### 2. Verify default-deny is active

```bash
# This should return 403 (denied by default policy)
curl -sk -H "Authorization: Bearer YOUR_API_KEY" \
  https://127.0.0.1:27124/vault/any-note.md
```

### 3. Add your first allow rule

**Option A — Settings UI:**
Settings > Local REST API NG > Access Rules > "Add Rule"

**Option B — Edit the rules file directly:**
Open `.obsidian/plugins/local-rest-api-ng/access-rules.conf` and add:

```
allow folder projects/**
```

### 4. Test access

```bash
# Allowed (matches folder rule)
curl -sk -H "Authorization: Bearer YOUR_API_KEY" \
  https://127.0.0.1:27124/vault/projects/readme.md

# Denied (no matching rule, default deny applies)
curl -sk -H "Authorization: Bearer YOUR_API_KEY" \
  https://127.0.0.1:27124/vault/private/secrets.md
```

### 5. Test directory listing (filtered)

```bash
# Only shows files in allowed folders
curl -sk -H "Authorization: Bearer YOUR_API_KEY" \
  https://127.0.0.1:27124/vault/
```

---

## Security Features

### Default-Deny Policy

When security filtering is enabled (the default), the **default policy is deny**. Any file that doesn't match an explicit allow rule is blocked. You can change this to "allow" in settings, but deny is strongly recommended.

### Access Rules File (`access-rules.conf`)

All filter rules are stored in a single human-readable file at:

```
.obsidian/plugins/local-rest-api-ng/access-rules.conf
```

This file is the **single source of truth** for all access rules. You can edit it directly in any text editor or manage rules through the Settings UI — both write to the same file.

**Format:**

```
# Comments start with #
# MODE  FILTER_TYPE  PATTERN  [METHODS]

allow  folder   PAI/**
allow  folder   Projects/**
deny   folder   Private/**
allow  name     *.md
deny   tag      #secret
deny   keyword  password        GET,POST
allow  folder   ~^(PAI|Public)/         # regex with ~ prefix
#!disabled deny folder Archived/**      # disabled rule (preserved but inactive)
```

| Field | Values | Description |
|-------|--------|-------------|
| `MODE` | `allow` \| `deny` | What to do when the rule matches |
| `FILTER_TYPE` | `folder` \| `name` \| `tag` \| `keyword` | Which filter to use |
| `PATTERN` | glob or `~regex` | Pattern to match against. Prefix with `~` for regex |
| `METHODS` | `GET,PUT,POST,PATCH,DELETE` | Optional. Comma-separated HTTP methods. Omit = all methods |

**Rules are evaluated top-to-bottom. First match wins.**

**Hot reload:** Changes made through the Settings UI take effect immediately. If you edit the file manually, re-open the Settings tab to trigger a reload, or toggle security filtering off/on.

### Folder Filter

Match files by their full vault-relative path using glob patterns or regex.

| Pattern | Type | Mode | Effect |
|---------|------|------|--------|
| `PAI/**` | Glob | Allow | Allow everything under `PAI/` (recursive) |
| `Private/**` | Glob | Deny | Deny everything under `Private/` |
| `~^(PAI\|Projects)/` | Regex | Allow | Allow `PAI/` or `Projects/` via regex |
| `**` | Glob | Allow | Allow everything (catch-all) |

Glob matching uses `minimatch` with `dot: true` (matches dotfiles like `.obsidian/`).

### Document Name Filter

Match files by their **basename** only (not the full path). The basename is extracted from the path before matching.

| Pattern | Type | Mode | Effect |
|---------|------|------|--------|
| `*.md` | Glob | Allow | Allow all markdown files |
| `secret-*` | Glob | Deny | Deny files starting with "secret-" |
| `^draft-` | Regex | Deny | Deny files with basename starting with "draft-" |

### Tag Filter

Match files by their Obsidian tags (both frontmatter `tags:` and inline `#tags`).

**Global tags** (configurable in settings, **highest priority — evaluated before ALL other rules**):

- **`#ai-deny`** — Files with this tag are **always denied**, overriding all other rules including folder allow.
- **`#ai-allow`** — Files with this tag are **always allowed**, overriding all other rules including folder deny.
- If both tags are present on the same file, **deny wins**.

Global tags are checked at position 0 in the evaluation chain, before folder and name rules. This means a file in a denied folder (e.g., `Restricted/`) can still be accessed if it has `#ai-allow`, and a file in an allowed folder (e.g., `Public/`) can be blocked if it has `#ai-deny`.

Custom tag rules can be added in `access-rules.conf`:

```
deny  tag  #confidential
allow tag  #public
```

**Usage in notes:**

```yaml
---
tags:
  - ai-allow
---
```

### Keyword Filter

Scan file content for specific strings or regex patterns. Useful for protecting files containing sensitive information.

| Pattern | Type | Mode | Effect |
|---------|------|------|--------|
| `password` | String | Deny | Deny files containing "password" |
| `SSN:` | String | Deny | Deny files containing "SSN:" |
| `~\b\d{3}-\d{2}-\d{4}\b` | Regex | Deny | Deny files with SSN-like patterns |

> **Fail-closed:** If a file can't be read for keyword scanning, it's denied.

### Per-Method Filtering

Each rule can optionally restrict which HTTP methods it applies to:

```
allow  folder  projects/**  GET          # Read-only access to projects
deny   folder  projects/**  PUT,DELETE   # Block writes and deletes
```

If no methods are specified, the rule applies to all methods.

**Example — read-only AI access:**

```
allow  folder  workspace/**  GET
```

Now `GET /vault/workspace/note.md` returns 200, but `PUT /vault/workspace/note.md` falls through to default deny → 403.

### Read-Only Mode

A global toggle that blocks **all** write operations (`PUT`, `POST`, `PATCH`, `DELETE`) on vault files, periodic notes, active files, and commands. GET requests are unaffected.

Enable in **Settings > Local REST API NG > Read-Only Mode**.

### Path Normalization

All incoming vault paths are normalized before filtering:
- Double slashes collapsed: `/PAI//foo/` → `PAI/foo/`
- Leading slashes stripped: `/notes/file.md` → `notes/file.md`
- Path traversal blocked: paths containing `..` or null bytes return `400 Bad Request`

### Audit & Logging

#### Access Log (`logs/access.log`)

All HTTP requests are logged in **Combined Log Format** (nginx/apache compatible):

```
127.0.0.1 - - [17/Feb/2026:15:30:42 +0100] "GET /vault/PAI/note.md HTTP/1.1" 200 1234 "-" "obsidian-mcp/1.0"
```

Location: `.obsidian/plugins/local-rest-api-ng/logs/access.log`

This log is compatible with standard log analysis tools (`GoAccess`, `AWStats`, `goaccess`, etc.).

#### Error Log (`logs/error.log`)

Security-relevant events are logged in **nginx error log format**:

```
2026/02/17 15:30:42 [warn] access denied by folder: Default policy: deny, client: 127.0.0.1, method: GET, path: /vault/private/secret.md, status: 403
```

Location: `.obsidian/plugins/local-rest-api-ng/logs/error.log`

Logged events:
- Access denials (with reason and filter type)
- Read-only mode blocks
- Path traversal attempts
- Filter engine errors
- Middleware exceptions

#### Log Viewer

View recent log entries directly in the Settings UI under the **Logs** section. Both access and error logs can be viewed via modal dialogs, and cleared with a single button.

### Filter Diagnostics

Test whether a vault path would be allowed or denied without making an API request:

**Settings > Local REST API NG > Filter Diagnostics** — enter a path and click "Test".

---

## Configuration Reference

### Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Enable Security Filtering | **ON** | Master toggle for the entire filter system |
| Default Policy | **Deny** | What happens when no rule matches (`deny` or `allow`) |
| Read-Only Mode | OFF | Block all write operations globally |
| Global Allow Tag | `#ai-allow` | Tag that always permits access |
| Global Deny Tag | `#ai-deny` | Tag that always blocks access (highest priority) |

### `access-rules.conf` Reference

```
# ──────────────────────────────────────────────────────────
# Obsidian Local REST API NG — Access Rules
# ──────────────────────────────────────────────────────────
#
# Format:  MODE  FILTER_TYPE  PATTERN  [METHODS]
#
#   MODE         allow | deny
#   FILTER_TYPE  folder | name | tag | keyword
#   PATTERN      glob pattern (or ~regex with tilde prefix)
#   METHODS      optional: comma-separated (GET,PUT,POST,PATCH,DELETE)
#
# Rules are evaluated top-to-bottom. First match wins.
# If no rule matches, the default policy from settings applies.
#
# Disable a rule without deleting it:
#   #!disabled allow folder SomeFolder/**
#
# ──────────────────────────────────────────────────────────

# Allow AI to read and write in the workspace
allow  folder  workspace/**

# Allow all markdown files by name
allow  name    *.md

# Block private folders
deny   folder  Private/**
deny   folder  .obsidian/**

# Block files containing sensitive keywords
deny   keyword password
deny   keyword ~\b\d{3}-\d{2}-\d{4}\b

# Read-only access to reference material
allow  folder  Reference/**  GET
```

---

## Common Configurations

### "AI can access my projects folder, nothing else"

```
# access-rules.conf
allow  folder  projects/**
```

Settings: Default Policy = **Deny**, Read-Only Mode = ON

### "AI can read everything except private notes"

```
# access-rules.conf
deny   folder  Private/**
deny   folder  Journal/**
deny   tag     #confidential
allow  folder  **
```

Settings: Default Policy = **Deny**

### "AI can read and write to a specific workspace"

```
# access-rules.conf
allow  folder  ai-workspace/**
```

Settings: Default Policy = **Deny**, Read-Only Mode = OFF

### "Read-only access everywhere, block sensitive content"

```
# access-rules.conf
deny   keyword password
deny   keyword ~\bSSN\b
deny   tag     #ai-deny
allow  folder  **  GET
```

Settings: Default Policy = **Deny**

---

## API Endpoints

All upstream endpoints are fully preserved:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/vault/{path}` | Read file content |
| PUT | `/vault/{path}` | Create/overwrite file |
| PATCH | `/vault/{path}` | Append/prepend/patch content |
| POST | `/vault/{path}` | Create file (error if exists) |
| DELETE | `/vault/{path}` | Delete file |
| GET | `/vault/` | List files in vault root |
| GET | `/vault/{dir}/` | List files in directory |
| GET | `/active/` | Get active file content |
| PUT | `/active/` | Update active file |
| PATCH | `/active/` | Append/prepend to active file |
| DELETE | `/active/` | Delete active file |
| GET | `/periodic/{period}` | Get periodic note |
| PUT | `/periodic/{period}` | Update periodic note |
| PATCH | `/periodic/{period}` | Append/prepend to periodic note |
| GET | `/search/simple/?query=...` | Simple text search |
| POST | `/search/` | JSON Logic search |
| GET | `/commands/` | List available commands |
| POST | `/commands/{id}` | Execute command |
| POST | `/open/{path}` | Open file in Obsidian |
| GET | `/` | Server status |
| GET | `/openapi.yaml` | OpenAPI specification |

For full API documentation, see the [upstream docs](https://coddingtonbear.github.io/obsidian-local-rest-api/).

---

## Building & Development

### Prerequisites

- Node.js >= 16
- npm

### Build

```bash
npm install
npm run build     # TypeScript check + esbuild → main.js
```

The build runs `tsc -noEmit -skipLibCheck` for type checking, then bundles with esbuild into a single `main.js` file (CJS format for Obsidian's Electron runtime).

### Development Build

```bash
npm run dev       # Watch mode — rebuilds on file changes
```

### Run Tests

```bash
npm test          # Run all Jest tests
```

**Test coverage:**

| Module | Tests | What's covered |
|--------|-------|----------------|
| `folder-filter` | 14 | Glob matching, regex, disabled rules, deny mode, dot files, first-match-wins |
| `document-name-filter` | 7 | Basename extraction, glob, regex, disabled rules |
| `rules-file` | 25 | Parsing, comments, `#!disabled`, regex `~` prefix, HTTP methods, line tracking, serialization, default template |
| `filter-engine` | 20 | Evaluation chain, global tag priority, default policy, folder/name rules, method filtering, filterPaths, filterSearchResults |
| `requestHandler` | 62 | All upstream API endpoint tests |

Total: **128 tests**

### MCP Integration Testing

The `testing_data/` directory contains a complete integration test suite for validating the security filter via MCP (Model Context Protocol) with a live Obsidian vault.

#### Test Data Structure

```
testing_data/
├── access-rules-testing.conf      # Pre-configured rules for all test cases
├── Testing-Guide.md               # Step-by-step test prompts and expected results
└── vault/                         # Test vault content (22 files, 9 folders)
    ├── Public/                    # T1: Folder allow
    ├── Restricted/                # T2: Folder deny
    ├── Archive/                   # T3: Folder deny + T13: disabled rule
    ├── Projects/                  # T4: Name deny (draft-*)
    ├── Notes/                     # T6-T8: Global tags + keywords
    ├── Shared/                    # T9+T11: Method restriction + eval order edge case
    ├── Research/                  # T10: Regex keyword deny
    ├── Templates/                 # T8: Keyword deny
    ├── .hidden-folder/            # T5: Regex name deny
    ├── tagged-allow.md            # T7: Global #ai-allow tag
    ├── tagged-deny.md             # T6: Global #ai-deny tag
    ├── normal-note.md             # T12: Default policy test
    └── draft-readme.md            # T4: Name deny (draft-*)
```

#### Setup

1. Copy `testing_data/vault/*` into your Obsidian vault
2. Copy `testing_data/access-rules-testing.conf` to `.obsidian/plugins/local-rest-api-ng/access-rules.conf`
3. Enable security filtering with default policy = deny
4. Set global allow tag = `#ai-allow`, global deny tag = `#ai-deny`

#### Test Cases (15 total)

| Test | Filter Type | Rule | Expected |
|------|------------|------|----------|
| T1 | Folder allow | `allow folder Public/**` | Public/ files accessible |
| T2 | Folder deny | `deny folder Restricted/**` | Restricted/ files blocked |
| T3 | Folder deny | `deny folder Archive/**` | Archive/ files blocked |
| T4 | Name deny | `deny name draft-*` | draft-* files blocked everywhere |
| T5 | Regex name | `deny name ~^\.` | Dot-prefixed paths blocked |
| T6 | Global deny tag | `#ai-deny` in settings | Tagged files always blocked |
| T7 | Global allow tag | `#ai-allow` in settings | Tagged files always allowed (overrides deny) |
| T8 | Keyword deny | `deny keyword secret` | Files containing "secret" blocked |
| T9 | Eval order | Folder allow vs keyword deny | Folder allow wins (first-match) |
| T10 | Regex keyword | `deny keyword ~confidential` | Regex keyword match blocks |
| T11 | Method filter | `allow folder Shared/** GET` | GET allowed, PUT/POST denied |
| T12 | Default policy | No matching rule | Denied by default policy |
| T13 | Disabled rule | `#!disabled allow folder Archive/**` | Disabled rule has no effect |
| T14 | Search filter | Search for denied content | Denied files excluded from results |
| T15 | Dir listing | List vault contents | Only allowed files/folders shown |

See `testing_data/Testing-Guide.md` for detailed MCP test prompts, expected results, and an expected results matrix for every test file.

### Project Structure

```
local-rest-api-ng/
├── src/
│   ├── main.ts                      # Plugin entry point, settings UI
│   ├── requestHandler.ts            # Express server, API routes
│   ├── types.ts                     # TypeScript types & interfaces
│   ├── constants.ts                 # Defaults, error codes
│   ├── securityFilterMiddleware.ts  # Security middleware (core)
│   ├── filters/
│   │   ├── filter-engine.ts         # FilterEngine — rule evaluation orchestrator
│   │   ├── rules-file.ts           # access-rules.conf parser & mutator
│   │   ├── folder-filter.ts         # Folder path matching (glob/regex)
│   │   ├── document-name-filter.ts  # Basename matching (glob/regex)
│   │   ├── tag-filter.ts           # Tag matching via MetadataCache
│   │   ├── keyword-filter.ts       # Content keyword scanning
│   │   ├── types.ts                # Filter type definitions
│   │   ├── folder-filter.test.ts
│   │   ├── document-name-filter.test.ts
│   │   ├── rules-file.test.ts
│   │   └── filter-engine.test.ts
│   ├── audit/
│   │   └── audit-logger.ts          # CLF access log + nginx error log
│   ├── api.ts                       # Public plugin API
│   └── utils.ts                     # Shared utilities
├── mocks/
│   └── obsidian.ts                  # Obsidian API mock for testing
├── testing_data/
│   ├── vault/                       # MCP integration test vault (22 test files)
│   ├── access-rules-testing.conf    # Pre-configured rules for test cases
│   └── Testing-Guide.md            # Step-by-step MCP test guide
├── docs/
│   └── openapi.yaml                 # OpenAPI specification
├── manifest.json                    # Obsidian plugin manifest
├── package.json
├── tsconfig.json
├── esbuild.config.mjs
└── jest.config.js
```

### Deploy

After building, copy these two files to your vault:

```bash
cp main.js manifest.json styles.css /path/to/vault/.obsidian/plugins/local-rest-api-ng/
```

Restart Obsidian or reload the plugin for changes to take effect.

### Files Generated at Runtime

The plugin creates these files in `.obsidian/plugins/local-rest-api-ng/`:

| File | Created When | Description |
|------|-------------|-------------|
| `access-rules.conf` | First enable | Filter rules (the main security config) |
| `logs/access.log` | First request | HTTP access log (CLF format) |
| `logs/error.log` | First security event | Error/deny log (nginx format) |
| `data.json` | Standard Obsidian | Plugin settings (managed by Obsidian) |

---

## Upstream Compatibility

This fork tracks [coddingtonbear/obsidian-local-rest-api](https://github.com/coddingtonbear/obsidian-local-rest-api). All upstream features work identically:

- REST API endpoints (`/vault/`, `/active/`, `/periodic/`, `/search/`, `/commands/`, `/open/`)
- HTTPS with self-signed certificates
- API key authentication
- Plugin extension API
- OpenAPI spec at `/openapi.yaml`

---

## Credits

Forked from [Adam Coddington's](https://coddingtonbear.net/) excellent [obsidian-local-rest-api](https://github.com/coddingtonbear/obsidian-local-rest-api).

## License

MIT (same as upstream)
