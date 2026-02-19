import type { FilterRule, FilterDecision } from "./types";

type TagResult =
  | { status: "found"; tags: string[] }
  | { status: "file_not_found" }
  | { status: "cache_unavailable" };

/**
 * Collect all tags from a file's cached metadata.
 * Returns a discriminated result:
 *   - "file_not_found" when the file doesn't exist in vault (e.g. POST creating new file)
 *   - "cache_unavailable" when file exists but MetadataCache has no entry
 *   - "found" with lowercase tags array when cache is available
 */
function collectFileTags(
  filePath: string,
  metadataCache: any,
  vault: any,
): TagResult {
  const file = vault.getAbstractFileByPath(filePath);
  if (!file) return { status: "file_not_found" };

  const cache = metadataCache.getFileCache(file);
  if (!cache) return { status: "cache_unavailable" };

  const tags: string[] = [];

  // From inline tags
  if (cache.tags) {
    for (const tc of cache.tags) {
      tags.push(tc.tag);
    }
  }

  // From frontmatter tags (add # prefix)
  if (cache.frontmatter?.tags) {
    for (const t of cache.frontmatter.tags) {
      const tag = t.startsWith("#") ? t : `#${t}`;
      tags.push(tag);
    }
  }

  return { status: "found", tags: tags.map((t) => t.toLowerCase()) };
}

/**
 * Check global tags (#ai-deny, #ai-allow) ONLY.
 * This runs BEFORE all other filters — global tags are the highest priority override.
 * Global deny trumps global allow.
 * Returns a FilterDecision if a global tag matches, null otherwise.
 */
export function checkGlobalTags(
  filePath: string,
  metadataCache: any,
  vault: any,
  globalAllowTag: string,
  globalDenyTag: string,
): FilterDecision | null {
  const result = collectFileTags(filePath, metadataCache, vault);

  // File doesn't exist yet (e.g. POST creating new file) — no tags to check,
  // let folder/name rules decide access
  if (result.status === "file_not_found") {
    return null;
  }

  // File exists but cache unavailable — fail-closed for security
  if (result.status === "cache_unavailable") {
    if (globalDenyTag || globalAllowTag) {
      return {
        allowed: false,
        reason: "Tag cache unavailable — denied (global tags configured)",
        filterType: "tag",
      };
    }
    return null;
  }

  const lowerTags = result.tags;

  // Global deny tag overrides everything — highest priority in the system
  if (globalDenyTag && lowerTags.includes(globalDenyTag.toLowerCase())) {
    return {
      allowed: false,
      reason: `Global deny tag "${globalDenyTag}" present`,
      filterType: "tag",
    };
  }

  // Global allow tag — overrides folder/name/keyword deny rules
  if (globalAllowTag && lowerTags.includes(globalAllowTag.toLowerCase())) {
    return {
      allowed: true,
      reason: `Global allow tag "${globalAllowTag}" present`,
      filterType: "tag",
    };
  }

  return null;
}

/**
 * Check a vault file's tags against custom tag filter rules using Obsidian's MetadataCache.
 * Zero-IO: uses only cached metadata.
 * This runs at position 3 in the chain (after folder and name rules).
 * Returns a FilterDecision if a rule matches, null otherwise.
 */
export function checkTagFilter(
  filePath: string,
  rules: FilterRule[],
  metadataCache: any,
  vault: any,
): FilterDecision | null {
  const result = collectFileTags(filePath, metadataCache, vault);

  // File doesn't exist yet (e.g. POST creating new file) — no tags to check,
  // let other filters decide access
  if (result.status === "file_not_found") {
    return null;
  }

  // File exists but cache unavailable — fail-closed for security
  if (result.status === "cache_unavailable") {
    return {
      allowed: false,
      reason: "Tag cache unavailable — denied (tag rules configured)",
      filterType: "tag",
    };
  }

  const lowerTags = result.tags;

  // Custom tag rules
  for (const rule of rules) {
    if (!rule.enabled) continue;

    let matched = false;

    if (rule.pattern.includes("+")) {
      // Compound AND logic: #draft+#internal matches only if ALL tags present
      const requiredTags = rule.pattern.split("+").map((t) => t.trim().toLowerCase());
      matched = requiredTags.every((rt) => lowerTags.some((t) => t === rt));
    } else {
      const ruleTag = rule.pattern.toLowerCase();
      matched = lowerTags.some((t) => t === ruleTag);
    }

    if (matched) {
      return {
        allowed: rule.mode === "allow",
        reason: `Tag filter: ${rule.mode} by tag "${rule.pattern}"`,
        matchedRule: rule,
        filterType: "tag",
      };
    }
  }

  return null;
}
