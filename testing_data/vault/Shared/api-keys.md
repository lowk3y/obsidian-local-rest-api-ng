---
tags: [credentials, shared]
---

# API Keys Document

This file contains the keyword "password" and should test evaluation order.

## Fake Credentials (TEST DATA ONLY)

- API Key: FAKE-1234-ABCD-5678
- password: not-a-real-password-just-testing
- Token: FAKE-TOKEN-FOR-TESTING

NOTE: Folder allow fires first (chain position 1), so keyword deny at position 4 may NOT fire.
First-match-wins means the Shared/ allow rule could override keyword deny.
This is an intentional edge case for testing evaluation order.
