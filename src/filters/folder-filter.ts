// eslint-disable-next-line @typescript-eslint/no-var-requires
const minimatch = require("minimatch") as (
  p: string,
  pattern: string,
  options?: { dot?: boolean },
) => boolean;
import type { FilterRule, FilterDecision } from "./types";

/**
 * Check a vault-relative file path against folder filter rules.
 * Matches the FULL file path against the pattern (not just the folder portion).
 * This means "PAI/**" matches both "PAI/file.md" and "PAI/sub/file.md".
 * Returns a FilterDecision if a rule matches, null otherwise.
 */
export function checkFolderFilter(
  filePath: string,
  rules: FilterRule[],
): FilterDecision | null {
  for (const rule of rules) {
    if (!rule.enabled) continue;

    let matched = false;

    if (rule.isRegex) {
      try {
        matched = new RegExp(rule.pattern).test(filePath);
      } catch {
        continue;
      }
    } else {
      // Match the full path so "PAI/**" matches "PAI/file.md"
      matched = minimatch(filePath, rule.pattern, { dot: true });
    }

    if (matched) {
      return {
        allowed: rule.mode === "allow",
        reason: `Folder filter: ${rule.mode} by pattern "${rule.pattern}"`,
        matchedRule: rule,
        filterType: "folder",
      };
    }
  }

  return null;
}
