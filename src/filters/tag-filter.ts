import type { FilterRule, FilterDecision } from "./types";

/**
 * Collect all tags from a file's cached metadata.
 * Returns lowercase tags array, or null if file/cache not found.
 */
function collectFileTags(
  filePath: string,
  metadataCache: any,
  vault: any,
): string[] | null {
  const file = vault.getAbstractFileByPath(filePath);
  if (!file) return null;

  const cache = metadataCache.getFileCache(file);
  if (!cache) return null;

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

  return tags.map((t) => t.toLowerCase());
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
  const lowerTags = collectFileTags(filePath, metadataCache, vault);
  if (!lowerTags) return null;

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
  const lowerTags = collectFileTags(filePath, metadataCache, vault);
  if (!lowerTags) return null;

  // Custom tag rules
  for (const rule of rules) {
    if (!rule.enabled) continue;

    const ruleTag = rule.pattern.toLowerCase();
    const matched = lowerTags.some((t) => t === ruleTag);

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
