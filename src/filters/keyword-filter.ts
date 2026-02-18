import type { FilterRule, FilterDecision } from "./types";

/**
 * Scan file content for keywords/patterns using vault.cachedRead().
 * Returns a FilterDecision if a rule matches, null otherwise.
 * Fail-closed: file read errors result in DENY.
 */
export async function checkKeywordFilter(
  filePath: string,
  rules: FilterRule[],
  vault: any,
): Promise<FilterDecision | null> {
  const file = vault.getAbstractFileByPath(filePath);
  if (!file) return null;

  let content: string | null = null;

  try {
    content = await vault.cachedRead(file);
  } catch {
    return {
      allowed: false,
      reason: "File read error",
      filterType: "keyword",
    };
  }

  try {
    for (const rule of rules) {
      if (!rule.enabled) continue;

      let matched = false;

      if (rule.isRegex) {
        try {
          matched = new RegExp(rule.pattern).test(content!);
        } catch {
          continue;
        }
      } else {
        matched = content!.indexOf(rule.pattern) !== -1;
      }

      if (matched) {
        return {
          allowed: rule.mode === "allow",
          reason: `Keyword filter: ${rule.mode} by pattern "${rule.pattern}"`,
          matchedRule: rule,
          filterType: "keyword",
        };
      }
    }

    return null;
  } finally {
    content = null;
  }
}
