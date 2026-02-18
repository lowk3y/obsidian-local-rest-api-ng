# Local REST API NG — Security Filter Testing Guide

## Overview

This guide provides step-by-step test cases for validating the security filter system via MCP (Model Context Protocol) integration with Obsidian. Each test maps to a specific rule in `access-rules-testing.conf`.

## Setup Instructions

### 1. Copy Test Vault Content

Copy the contents of `testing_data/vault/` into your Obsidian vault:

```bash
cp -r testing_data/vault/* /path/to/your/obsidian/vault/
```

### 2. Install Access Rules

Copy the test rules to the plugin config directory:

```bash
cp testing_data/access-rules-testing.conf \
   /path/to/vault/.obsidian/plugins/local-rest-api-ng/access-rules.conf
```

### 3. Configure Plugin Settings

In Obsidian Settings → Local REST API NG:

- **Security Filter**: Enabled
- **Default Policy**: `deny` (most tests assume deny-by-default)
- **Global Allow Tag**: `#ai-allow`
- **Global Deny Tag**: `#ai-deny`
- **Read-Only Mode**: Disabled (enable for specific tests)

### 4. Restart/Reload

After copying rules, the plugin should hot-reload. If not, toggle the plugin off/on.

---

## Test Vault Structure

```
Vault Root/
├── Public/
│   ├── welcome.md                 # T1: Should be ALLOWED (folder allow)
│   └── getting-started.md         # T1: Should be ALLOWED (folder allow)
├── Restricted/
│   ├── personal-journal.md        # T2: Should be DENIED (folder deny)
│   └── finances.md                # T2: Should be DENIED (folder deny)
├── Projects/
│   ├── project-alpha.md           # No matching rule → default policy
│   └── draft-project-beta.md      # T4: Should be DENIED (name: draft-*)
├── Notes/
│   ├── meeting-notes.md           # T7: Should be ALLOWED (#ai-allow tag)
│   ├── secret-plans.md            # T6+T8: DENIED (#ai-deny + keyword "secret")
│   └── ideas.md                   # No matching rule → default policy
├── Archive/
│   ├── old-report.md              # T3+T13: DENIED (folder deny, disabled allow)
│   └── 2024-summary.md            # T3: Should be DENIED (folder deny)
├── Shared/
│   ├── team-doc.md                # T11: ALLOWED for GET, DENIED for PUT
│   └── api-keys.md                # T11+T9: Edge case (see test details)
├── Research/
│   ├── ai-paper-notes.md          # No matching rule → default policy
│   └── confidential-research.md   # T10: DENIED (regex keyword "confidential")
├── Templates/
│   ├── daily-note-template.md     # No matching rule → default policy
│   └── secret-template.md         # T8: DENIED (keyword "secret")
├── .hidden-folder/
│   └── hidden-note.md             # T5: DENIED (regex name ~^\.)
├── tagged-allow.md                # T7: Should be ALLOWED (#ai-allow tag)
├── tagged-deny.md                 # T6: Should be DENIED (#ai-deny tag)
├── normal-note.md                 # T12: Default policy test
└── draft-readme.md                # T4: DENIED (name: draft-*)
```

---

## Test Cases

### T1: Folder Allow — Public/**

**Rule:** `allow folder Public/**`
**Expected:** Files in Public/ are accessible

**MCP Test Prompt:**
> "Read the file `Public/welcome.md` from my Obsidian vault"

**Expected Result:** Content of welcome.md is returned successfully.

**MCP Test Prompt:**
> "List all files in the `Public` folder in my Obsidian vault"

**Expected Result:** Shows `welcome.md` and `getting-started.md`.

**Pass Criteria:**
- [ ] `Public/welcome.md` content is readable
- [ ] `Public/getting-started.md` content is readable
- [ ] Directory listing shows both files

---

### T2: Folder Deny — Restricted/**

**Rule:** `deny folder Restricted/**`
**Expected:** Files in Restricted/ are blocked

**MCP Test Prompt:**
> "Read the file `Restricted/personal-journal.md` from my Obsidian vault"

**Expected Result:** Access denied or empty response — content should NOT be returned.

**MCP Test Prompt:**
> "List all files in the `Restricted` folder"

**Expected Result:** Empty listing or access denied.

**Pass Criteria:**
- [ ] `Restricted/personal-journal.md` content is NOT readable
- [ ] `Restricted/finances.md` content is NOT readable
- [ ] No Restricted/ files appear in vault-wide searches

---

### T3: Folder Deny — Archive/**

**Rule:** `deny folder Archive/**`
**Expected:** Archived files are blocked

**MCP Test Prompt:**
> "Read `Archive/old-report.md` from my vault"

**Expected Result:** Access denied.

**Pass Criteria:**
- [ ] `Archive/old-report.md` is NOT readable
- [ ] `Archive/2024-summary.md` is NOT readable

---

### T4: Document Name Deny — draft-*

**Rule:** `deny name draft-*`
**Expected:** Any file starting with "draft-" is blocked regardless of folder

**MCP Test Prompt:**
> "Read the file `draft-readme.md` from the root of my vault"

**MCP Test Prompt:**
> "Read `Projects/draft-project-beta.md` from my vault"

**Expected Result:** Both files should be denied.

**Pass Criteria:**
- [ ] `draft-readme.md` at root is NOT readable
- [ ] `Projects/draft-project-beta.md` is NOT readable
- [ ] `Projects/project-alpha.md` IS readable (doesn't match `draft-*`)

---

### T5: Regex Name Deny — Hidden Files (~^\.)

**Rule:** `deny name ~^\.`
**Expected:** Files/folders starting with a dot are blocked

**MCP Test Prompt:**
> "Read `.hidden-folder/hidden-note.md` from my vault"

**Expected Result:** Access denied.

**Note:** Obsidian may not index dot-prefixed folders at all, making this a defense-in-depth test.

**Pass Criteria:**
- [ ] `.hidden-folder/hidden-note.md` is NOT readable
- [ ] File does not appear in search results

---

### T6: Global Deny Tag — #ai-deny

**Rule:** Configured in plugin settings: Global Deny Tag = `#ai-deny`
**Expected:** Files with #ai-deny tag are always blocked

**MCP Test Prompt:**
> "Read the file `tagged-deny.md` from my vault"

**MCP Test Prompt:**
> "Read `Notes/secret-plans.md` from my vault"

**Expected Result:** Both files should be denied.

**Pass Criteria:**
- [ ] `tagged-deny.md` is NOT readable
- [ ] `Notes/secret-plans.md` is NOT readable (has both #ai-deny and keyword "secret")

---

### T7: Global Allow Tag — #ai-allow

**Rule:** Configured in plugin settings: Global Allow Tag = `#ai-allow`
**Expected:** Files with #ai-allow tag are accessible even with deny-by-default

**MCP Test Prompt:**
> "Read `tagged-allow.md` from my vault"

**MCP Test Prompt:**
> "Read `Notes/meeting-notes.md` from my vault"

**Expected Result:** Both files should be accessible.

**Pass Criteria:**
- [ ] `tagged-allow.md` IS readable
- [ ] `Notes/meeting-notes.md` IS readable
- [ ] Content is correctly returned

---

### T8: Keyword Deny — "secret"

**Rule:** `deny keyword secret`
**Expected:** Files containing the word "secret" are blocked

**MCP Test Prompt:**
> "Read `Templates/secret-template.md` from my vault"

**MCP Test Prompt:**
> "Search my vault for the word 'secret'"

**Expected Result:** File content denied. Search should NOT return files containing "secret" (or return them but with access blocked).

**Pass Criteria:**
- [ ] `Templates/secret-template.md` is NOT readable
- [ ] `Notes/secret-plans.md` is NOT readable
- [ ] Search for "secret" does not expose denied file content

---

### T9: Keyword Deny — "password"

**Rule:** `deny keyword password`
**Expected:** Files containing "password" are blocked

**MCP Test Prompt:**
> "Read `Shared/api-keys.md` from my vault"

**⚠️ EDGE CASE:** `Shared/api-keys.md` has BOTH a folder allow rule (`allow folder Shared/** GET`) and contains the keyword "password". The filter uses **first-match-wins**: folder rules evaluate before keyword rules. The folder allow at chain position 1 will match before keyword deny at position 4. **Expected: ALLOWED for GET** (folder allow fires first).

**Pass Criteria:**
- [ ] `Shared/api-keys.md` IS readable via GET (folder allow wins)
- [ ] This documents the first-match-wins evaluation order

---

### T10: Regex Keyword Deny — "confidential"

**Rule:** `deny keyword ~confidential`
**Expected:** Files matching the regex keyword are blocked

**MCP Test Prompt:**
> "Read `Research/confidential-research.md` from my vault"

**Expected Result:** Access denied.

**Pass Criteria:**
- [ ] `Research/confidential-research.md` is NOT readable
- [ ] `Research/ai-paper-notes.md` IS readable (no matching keyword)

---

### T11: HTTP Method Restriction — Shared/** GET only

**Rule:** `allow folder Shared/** GET`
**Expected:** Shared files readable but not writable

**MCP Test Prompt (READ — should work):**
> "Read `Shared/team-doc.md` from my vault"

**MCP Test Prompt (WRITE — should fail):**
> "Append 'TEST WRITE' to `Shared/team-doc.md` in my vault"

**Expected Result:** Read succeeds, write fails.

**Note:** MCP write operations use PUT/POST methods. The rule only allows GET.

**Pass Criteria:**
- [ ] `Shared/team-doc.md` IS readable (GET allowed)
- [ ] Writing to `Shared/team-doc.md` is DENIED (PUT/POST not allowed)

---

### T12: Default Policy — No Rules Match

**Rule:** Default policy = `deny` (no matching rules)
**Expected:** Files with no matching rules are denied

**MCP Test Prompt:**
> "Read `normal-note.md` from my vault"

**MCP Test Prompt:**
> "Read `Notes/ideas.md` from my vault"

**Expected Result:** Both denied (no allow rule matches, default is deny).

**Pass Criteria:**
- [ ] `normal-note.md` is NOT readable (default deny)
- [ ] `Notes/ideas.md` is NOT readable (default deny)
- [ ] `Research/ai-paper-notes.md` is NOT readable (default deny)

**Bonus — Switch to allow default:**
Change default policy to `allow` in settings, then retry. All three should become accessible.

---

### T13: Disabled Rule — #!disabled

**Rule:** `#!disabled allow folder Archive/**`
**Expected:** Disabled rule has no effect — Archive/ stays denied

**MCP Test Prompt:**
> "Read `Archive/old-report.md` from my vault"

**Expected Result:** Still denied. The disabled allow rule should NOT override the active deny rule.

**Pass Criteria:**
- [ ] `Archive/old-report.md` is NOT readable
- [ ] Enabling the rule (removing `#!disabled` prefix) would make it accessible

---

### T14: Search Filtering

**Rule:** All deny rules should filter search results
**Expected:** Denied files don't appear in search

**MCP Test Prompt:**
> "Search my Obsidian vault for 'journal'"

**Expected Result:** `Restricted/personal-journal.md` should NOT appear (folder deny).

**MCP Test Prompt:**
> "Search my vault for 'template'"

**Expected Result:** `Templates/daily-note-template.md` behavior depends on default policy. `Templates/secret-template.md` should be filtered (keyword "secret").

**MCP Test Prompt:**
> "Search my vault for 'report'"

**Expected Result:** `Archive/old-report.md` should NOT appear (folder deny).

**Pass Criteria:**
- [ ] Search for "journal" does NOT return Restricted/ files
- [ ] Search for "secret" does NOT return denied files
- [ ] Search for "report" does NOT return Archive/ files
- [ ] Search for "welcome" DOES return Public/welcome.md

---

### T15: Directory Listing Filtering

**Rule:** All deny rules should filter directory listings
**Expected:** Denied files stripped from listings

**MCP Test Prompt:**
> "List all files in my Obsidian vault"

**Expected Result:** Should show Public/ files, Shared/ files (GET), tagged-allow.md. Should NOT show Restricted/, Archive/, draft-*, files with denied keywords.

**Pass Criteria:**
- [ ] Public/ files appear in listing
- [ ] Restricted/ files do NOT appear
- [ ] Archive/ files do NOT appear
- [ ] `draft-readme.md` does NOT appear
- [ ] `tagged-deny.md` does NOT appear

---

## Quick Reference: Expected Results Matrix

| File | Folder | Name | Tag | Keyword | Expected |
|------|--------|------|-----|---------|----------|
| Public/welcome.md | ALLOW | — | — | — | **ALLOW** |
| Public/getting-started.md | ALLOW | — | — | — | **ALLOW** |
| Restricted/personal-journal.md | DENY | — | — | — | **DENY** |
| Restricted/finances.md | DENY | — | — | — | **DENY** |
| Projects/project-alpha.md | — | — | — | — | **default** |
| Projects/draft-project-beta.md | — | DENY | — | — | **DENY** |
| Notes/meeting-notes.md | — | — | ALLOW | — | **ALLOW** |
| Notes/secret-plans.md | — | — | DENY | DENY | **DENY** |
| Notes/ideas.md | — | — | — | — | **default** |
| Archive/old-report.md | DENY | — | — | — | **DENY** |
| Archive/2024-summary.md | DENY | — | — | — | **DENY** |
| Shared/team-doc.md | ALLOW(GET) | — | — | — | **ALLOW(GET)** |
| Shared/api-keys.md | ALLOW(GET) | — | — | (password) | **ALLOW(GET)** ⚠️ |
| Research/ai-paper-notes.md | — | — | — | — | **default** |
| Research/confidential-research.md | — | — | — | DENY | **DENY** |
| Templates/daily-note-template.md | — | — | — | — | **default** |
| Templates/secret-template.md | — | — | — | DENY | **DENY** |
| .hidden-folder/hidden-note.md | — | DENY | — | — | **DENY** |
| tagged-allow.md | — | — | ALLOW | — | **ALLOW** |
| tagged-deny.md | — | — | DENY | — | **DENY** |
| normal-note.md | — | — | — | — | **default** |
| draft-readme.md | — | DENY | — | — | **DENY** |

**Legend:**
- `ALLOW` = File should be accessible
- `DENY` = File should be blocked
- `default` = Depends on default policy setting (deny = blocked, allow = accessible)
- `ALLOW(GET)` = Accessible for read, blocked for write
- ⚠️ = Edge case where evaluation order matters

---

## Evaluation Order Reminder

The filter chain evaluates in this order (first match wins):

```
1. Folder rules    → checked first
2. Name rules      → checked second
3. Tag rules       → checked third (global tags have priority)
4. Keyword rules   → checked fourth (reads file content)
5. Default policy  → fallback if nothing matched
```

This means:
- A folder ALLOW will fire before a keyword DENY (see T9: api-keys.md)
- A folder DENY will fire before a tag ALLOW
- Global deny tag has highest priority within tag evaluation

---

## Troubleshooting

### Security filter not working at all
- Check plugin settings → Security Filter must be **Enabled**
- Verify `access-rules.conf` exists in plugin config directory
- Check Obsidian developer console for filter-related errors

### Rules not applying after edit
- The plugin should hot-reload rules on file change
- If not, toggle the plugin off/on in Obsidian settings

### MCP can read denied files
- Verify the MCP server is connecting through the local REST API (not directly)
- Check that API key authentication is configured
- Ensure the security filter middleware is in the request chain

### Search returns denied files
- This is a known design consideration (Finding F10 from security review)
- Search reads files first, then post-filters results
- File content was processed server-side even though results are filtered
