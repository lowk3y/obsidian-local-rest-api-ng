import type { DataAdapter } from "obsidian";
import type { FilterRule, FilterMode, HttpMethod } from "./types";

/**
 * Parse an access-rules.conf file into FilterRule arrays grouped by filter type.
 *
 * File format (one rule per line):
 *   # Comments start with #
 *   #!disabled MODE FILTER_TYPE PATTERN [METHODS]   ← disabled rule
 *   MODE FILTER_TYPE PATTERN [METHODS]
 *
 * MODE:        allow | deny
 * FILTER_TYPE: folder | name | tag | keyword
 * PATTERN:     glob pattern, or ~regex for regex patterns
 *              Use double quotes for patterns with spaces: "00 Workpad/**"
 *              Regex patterns support /i flag for case-insensitive: ~pattern/i
 *              Tag patterns support + for AND logic: #draft+#internal
 * METHODS:     optional comma-separated HTTP methods (GET,PUT,POST,PATCH,DELETE)
 *
 * Examples:
 *   allow folder PAI/**
 *   allow folder Projects/**
 *   deny  folder Private/**
 *   allow folder "00 Workpad/**"          # quoted pattern (spaces in name)
 *   allow name   *.md
 *   deny  tag    #secret
 *   deny  tag    #draft+#internal         # deny only if ALL tags present
 *   deny  keyword password  GET,POST
 *   deny  keyword ~password/i             # case-insensitive regex
 *   allow folder ~^(PAI|Projects)/        # regex with ~ prefix
 *   #!disabled deny folder Archived/**    # disabled rule
 */

export interface ParsedRules {
  folder: FilterRule[];
  name: FilterRule[];
  tag: FilterRule[];
  keyword: FilterRule[];
}

/** A rule with its original line number and filter type for UI editing */
export interface RuleEntry {
  rule: FilterRule;
  filterType: "folder" | "name" | "tag" | "keyword";
  lineNumber: number; // 0-based line index in the file
}

const VALID_MODES = new Set(["allow", "deny"]);
const VALID_TYPES = new Set(["folder", "name", "tag", "keyword"]);
const VALID_METHODS = new Set(["GET", "PUT", "POST", "PATCH", "DELETE"]);
const DISABLED_PREFIX = "#!disabled ";

/**
 * Parse a single rule line (already trimmed, not empty, not a regular comment).
 * Returns a RuleEntry or null if the line is invalid.
 */
function parseRuleLine(
  line: string,
  lineIndex: number,
): RuleEntry | null {
  // Check for disabled rule
  let enabled = true;
  let content = line;
  if (line.startsWith(DISABLED_PREFIX)) {
    enabled = false;
    content = line.slice(DISABLED_PREFIX.length).trim();
  }

  // Split only the first two tokens (mode and type) on whitespace,
  // then handle the remainder specially to support quoted patterns with spaces.
  // e.g.: allow  folder  "00 Workpad/**"  GET,POST
  const firstSplit = content.match(/^(\S+)\s+(\S+)\s+([\s\S]*)$/);
  if (!firstSplit) {
    console.warn(
      `[REST API] access-rules.conf line ${lineIndex + 1}: expected at least 3 fields: "${line}"`,
    );
    return null;
  }

  const [, modeStr, typeStr, remainder] = firstSplit;
  let pattern: string;
  let methodsStr: string | undefined;

  const trimmedRemainder = remainder.trim();
  if (trimmedRemainder.startsWith('"')) {
    // Quoted pattern — extract content between double quotes
    const closeQuote = trimmedRemainder.indexOf('"', 1);
    if (closeQuote === -1) {
      console.warn(
        `[REST API] access-rules.conf line ${lineIndex + 1}: unterminated quoted pattern: "${line}"`,
      );
      return null;
    }
    pattern = trimmedRemainder.slice(1, closeQuote);
    const afterQuote = trimmedRemainder.slice(closeQuote + 1).trim();
    methodsStr = afterQuote || undefined;
  } else {
    // Unquoted pattern — split on whitespace (existing behavior)
    const remainderParts = trimmedRemainder.split(/\s+/);
    pattern = remainderParts[0];
    methodsStr = remainderParts[1];
  }

  if (!pattern) {
    console.warn(
      `[REST API] access-rules.conf line ${lineIndex + 1}: empty pattern: "${line}"`,
    );
    return null;
  }

  const mode = modeStr.toLowerCase();
  if (!VALID_MODES.has(mode)) {
    console.warn(
      `[REST API] access-rules.conf line ${lineIndex + 1}: invalid mode "${modeStr}" (expected allow|deny)`,
    );
    return null;
  }

  const filterType = typeStr.toLowerCase();
  if (!VALID_TYPES.has(filterType)) {
    console.warn(
      `[REST API] access-rules.conf line ${lineIndex + 1}: invalid type "${typeStr}" (expected folder|name|tag|keyword)`,
    );
    return null;
  }

  // Detect regex patterns (prefixed with ~) and extract optional flags (e.g., /i)
  const isRegex = pattern.startsWith("~");
  let cleanPattern = isRegex ? pattern.slice(1) : pattern;
  let regexFlags: string | undefined;

  if (isRegex) {
    // Extract trailing flags: ~pattern/i → pattern="pattern", flags="i"
    const flagMatch = cleanPattern.match(/\/([gimsuy]+)$/);
    if (flagMatch) {
      regexFlags = flagMatch[1];
      cleanPattern = cleanPattern.slice(0, -flagMatch[0].length);
    }
  }

  // Parse optional methods
  let methods: HttpMethod[] | undefined;
  if (methodsStr) {
    methods = methodsStr
      .split(",")
      .map((m) => m.trim().toUpperCase())
      .filter((m) => VALID_METHODS.has(m)) as HttpMethod[];
    if (methods.length === 0) methods = undefined;
  }

  const rule: FilterRule = {
    id: `rule-line-${lineIndex + 1}`,
    mode: mode as FilterMode,
    pattern: cleanPattern,
    isRegex,
    enabled,
    description: `line ${lineIndex + 1}`,
    methods,
    regexFlags,
  };

  return {
    rule,
    filterType: filterType as RuleEntry["filterType"],
    lineNumber: lineIndex,
  };
}

/**
 * Parse the full access-rules.conf content.
 * Returns grouped rules (for FilterEngine) and a flat list with line numbers (for UI).
 */
export function parseRulesFile(content: string): {
  grouped: ParsedRules;
  entries: RuleEntry[];
} {
  const grouped: ParsedRules = {
    folder: [],
    name: [],
    tag: [],
    keyword: [],
  };
  const entries: RuleEntry[] = [];

  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Skip empty lines and regular comments (but not #!disabled)
    if (!line) continue;
    if (line.startsWith("#") && !line.startsWith(DISABLED_PREFIX)) continue;

    const entry = parseRuleLine(line, i);
    if (!entry) continue;

    entries.push(entry);
    // Only add enabled rules to the grouped structure (used by FilterEngine)
    if (entry.rule.enabled) {
      grouped[entry.filterType].push(entry.rule);
    }
  }

  return { grouped, entries };
}

/**
 * Serialize a single rule into a conf file line.
 */
export function serializeRule(
  filterType: string,
  rule: FilterRule,
): string {
  const prefix = rule.enabled ? "" : DISABLED_PREFIX;
  const flagSuffix = rule.isRegex && rule.regexFlags ? `/${rule.regexFlags}` : "";
  const rawPattern = rule.isRegex ? `~${rule.pattern}${flagSuffix}` : rule.pattern;
  // Quote the pattern if it contains spaces
  const patternStr = rawPattern.includes(" ") ? `"${rawPattern}"` : rawPattern;
  const methodStr =
    rule.methods && rule.methods.length > 0
      ? `  ${rule.methods.join(",")}`
      : "";
  return `${prefix}${rule.mode}  ${filterType}  ${patternStr}${methodStr}`;
}

/**
 * Load and parse the access-rules.conf file from the plugin directory.
 * Returns null if the file doesn't exist.
 */
export async function loadRulesFile(
  adapter: DataAdapter,
  pluginDir: string,
): Promise<{ grouped: ParsedRules; entries: RuleEntry[] } | null> {
  const rulesPath = `${pluginDir}/access-rules.conf`;

  try {
    const exists = await adapter.exists(rulesPath);
    if (!exists) {
      return null;
    }
    const content = await adapter.read(rulesPath);
    const result = parseRulesFile(content);
    const total =
      result.grouped.folder.length +
      result.grouped.name.length +
      result.grouped.tag.length +
      result.grouped.keyword.length;
    console.log(
      `[REST API] Loaded ${total} active rules (${result.entries.length} total) from access-rules.conf`,
    );
    return result;
  } catch (err) {
    console.error("[REST API] Failed to load access-rules.conf:", err);
    return null;
  }
}

/**
 * Read the raw file content, apply a line-level mutation, and write back.
 */
async function mutateFile(
  adapter: DataAdapter,
  pluginDir: string,
  mutator: (lines: string[]) => string[],
): Promise<void> {
  const rulesPath = `${pluginDir}/access-rules.conf`;
  let content = "";
  try {
    content = await adapter.read(rulesPath);
  } catch {
    // File doesn't exist yet — start empty
  }
  const lines = content.split("\n");
  const updated = mutator(lines);
  await adapter.write(rulesPath, updated.join("\n"));
}

/**
 * Append a new rule to the end of access-rules.conf.
 */
export async function appendRule(
  adapter: DataAdapter,
  pluginDir: string,
  filterType: string,
  rule: FilterRule,
): Promise<void> {
  const line = serializeRule(filterType, rule);
  await mutateFile(adapter, pluginDir, (lines) => {
    // Ensure trailing newline before appending
    if (lines.length > 0 && lines[lines.length - 1].trim() !== "") {
      lines.push("");
    }
    lines.push(line);
    return lines;
  });
}

/**
 * Remove a rule by its 0-based line number.
 */
export async function removeRuleByLine(
  adapter: DataAdapter,
  pluginDir: string,
  lineNumber: number,
): Promise<void> {
  await mutateFile(adapter, pluginDir, (lines) => {
    if (lineNumber >= 0 && lineNumber < lines.length) {
      lines.splice(lineNumber, 1);
    }
    return lines;
  });
}

/**
 * Toggle a rule's enabled state by commenting/uncommenting its line.
 */
export async function toggleRuleByLine(
  adapter: DataAdapter,
  pluginDir: string,
  lineNumber: number,
  enabled: boolean,
): Promise<void> {
  await mutateFile(adapter, pluginDir, (lines) => {
    if (lineNumber < 0 || lineNumber >= lines.length) return lines;
    const line = lines[lineNumber].trim();

    if (enabled && line.startsWith(DISABLED_PREFIX)) {
      // Re-enable: remove the #!disabled prefix
      lines[lineNumber] = line.slice(DISABLED_PREFIX.length);
    } else if (!enabled && !line.startsWith(DISABLED_PREFIX)) {
      // Disable: add the #!disabled prefix
      lines[lineNumber] = DISABLED_PREFIX + line;
    }
    return lines;
  });
}

/**
 * Generate a default access-rules.conf template.
 */
export function generateDefaultRulesFile(): string {
  return `# ──────────────────────────────────────────────────────────────
# Obsidian Local REST API NG — Access Rules
# ──────────────────────────────────────────────────────────────
#
# Format:  MODE  FILTER_TYPE  PATTERN  [METHODS]
#
#   MODE         allow | deny
#   FILTER_TYPE  folder | name | tag | keyword
#   PATTERN      glob pattern (or ~regex with tilde prefix)
#                Quote patterns with spaces: "00 Workpad/**"
#                Regex flags: ~pattern/i for case-insensitive
#                Tag AND logic: #tag1+#tag2 (deny only if ALL present)
#   METHODS      optional: comma-separated (GET,PUT,POST,PATCH,DELETE)
#
# Rules are evaluated top-to-bottom. First match wins.
# If no rule matches, the default policy from settings applies.
#
# Disable a rule without deleting it:
#   #!disabled allow folder SomeFolder/**
#
# Examples:
#   allow folder PAI/**
#   allow folder Projects/**
#   deny  folder Private/**
#   allow folder "00 Workpad/**"       # quote patterns with spaces
#   allow name   *.md
#   deny  tag    #secret
#   deny  tag    #draft+#internal      # deny only if ALL tags present
#   deny  keyword password             GET,POST
#   deny  keyword ~password/i          # case-insensitive regex match
#   allow folder ~^(PAI|Public)/       # regex with ~ prefix
#
# ──────────────────────────────────────────────────────────────

# Add your rules below:

`;
}
