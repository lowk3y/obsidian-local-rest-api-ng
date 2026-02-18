// eslint-disable-next-line @typescript-eslint/no-var-requires
const minimatch = require("minimatch") as (
  p: string,
  pattern: string,
  options?: { dot?: boolean },
) => boolean;
import type { FilterRule, FilterDecision } from "./types";

/**
 * Check a vault-relative file path's basename against document name filter rules.
 * Returns a FilterDecision if a rule matches, null otherwise.
 */
export function checkDocumentNameFilter(
  filePath: string,
  rules: FilterRule[],
): FilterDecision | null {
  const lastSlash = filePath.lastIndexOf("/");
  const basename = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;

  for (const rule of rules) {
    if (!rule.enabled) continue;

    let matched = false;

    if (rule.isRegex) {
      try {
        matched = new RegExp(rule.pattern).test(basename);
      } catch {
        continue;
      }
    } else {
      matched = minimatch(basename, rule.pattern, { dot: true });
    }

    if (matched) {
      return {
        allowed: rule.mode === "allow",
        reason: `Document name filter: ${rule.mode} by pattern "${rule.pattern}"`,
        matchedRule: rule,
        filterType: "document-name",
      };
    }
  }

  return null;
}
