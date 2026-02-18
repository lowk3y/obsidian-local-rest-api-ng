import type { App, DataAdapter } from "obsidian";
import type {
  FilterDecision,
  FilterMode,
  FilterRule,
  HttpMethod,
} from "./types";
import type { ParsedRules } from "./rules-file";
import { checkFolderFilter } from "./folder-filter";
import { checkDocumentNameFilter } from "./document-name-filter";
import { checkGlobalTags, checkTagFilter } from "./tag-filter";
import { checkKeywordFilter } from "./keyword-filter";
import { loadRulesFile } from "./rules-file";

export class FilterEngine {
  /** Rules loaded from access-rules.conf */
  fileRules: ParsedRules | null = null;

  constructor(private app: App) {}

  /**
   * Check if the HTTP method is allowed by the rule.
   * If rule has no methods restriction, all methods are allowed.
   */
  private methodAllowed(
    rule: FilterRule | undefined,
    method: string,
  ): boolean {
    if (!rule?.methods || rule.methods.length === 0) return true;
    return rule.methods.includes(method.toUpperCase() as HttpMethod);
  }

  /**
   * Reload rules from access-rules.conf. Called after UI edits or manual changes.
   */
  async reloadRules(
    adapter: DataAdapter,
    pluginDir: string,
  ): Promise<void> {
    const result = await loadRulesFile(adapter, pluginDir);
    this.fileRules = result?.grouped ?? null;
  }

  /**
   * Evaluate a single file path against the filter chain.
   * Rules come from access-rules.conf (fileRules).
   * Order: folder -> document-name -> tag -> keyword -> default policy.
   * Returns FilterDecision with allow/deny and reason.
   */
  async evaluateFile(
    filePath: string,
    settings: {
      defaultPolicy: FilterMode;
      globalAllowTag: string;
      globalDenyTag: string;
    },
    method?: string,
  ): Promise<FilterDecision> {
    // 0. Global tags — highest priority, checked BEFORE all other rules.
    //    #ai-deny always denies (even if folder/name would allow).
    //    #ai-allow always allows (even if folder/name would deny).
    const globalTagResult = checkGlobalTags(
      filePath,
      this.app.metadataCache,
      this.app.vault,
      settings.globalAllowTag,
      settings.globalDenyTag,
    );
    if (globalTagResult) {
      return globalTagResult;
    }

    if (this.fileRules) {
      // 1. Folder rules
      if (this.fileRules.folder.length > 0) {
        const result = checkFolderFilter(filePath, this.fileRules.folder);
        if (
          result &&
          (!method || this.methodAllowed(result.matchedRule, method))
        ) {
          return result;
        }
      }

      // 2. Document name rules
      if (this.fileRules.name.length > 0) {
        const result = checkDocumentNameFilter(
          filePath,
          this.fileRules.name,
        );
        if (
          result &&
          (!method || this.methodAllowed(result.matchedRule, method))
        ) {
          return result;
        }
      }

      // 3. Custom tag rules (non-global tags from access-rules.conf)
      if (this.fileRules.tag.length > 0) {
        const result = checkTagFilter(
          filePath,
          this.fileRules.tag,
          this.app.metadataCache,
          this.app.vault,
        );
        if (
          result &&
          (!method || this.methodAllowed(result.matchedRule, method))
        ) {
          return result;
        }
      }

      // 4. Keyword rules
      if (this.fileRules.keyword.length > 0) {
        const result = await checkKeywordFilter(
          filePath,
          this.fileRules.keyword,
          this.app.vault,
        );
        if (
          result &&
          (!method || this.methodAllowed(result.matchedRule, method))
        ) {
          return result;
        }
      }
    }

    // 5. Default policy
    return {
      allowed: settings.defaultPolicy === "allow",
      reason: `Default policy: ${settings.defaultPolicy}`,
    };
  }

  /**
   * Filter an array of vault paths, returning only allowed paths.
   * Used for directory listing and search result post-filtering.
   */
  async filterPaths(paths: string[], settings: any): Promise<string[]> {
    const results = await Promise.all(
      paths.map(async (p) => {
        const decision = await this.evaluateFile(p, settings, "GET");
        return decision.allowed ? p : null;
      }),
    );
    return results.filter((p): p is string => p !== null);
  }

  /**
   * Filter search results array, stripping denied files.
   * Works with both simple search (filename field) and JSON search.
   */
  async filterSearchResults(
    results: any[],
    settings: any,
  ): Promise<any[]> {
    const filtered = await Promise.all(
      results.map(async (item) => {
        const path = item.filename ?? item.path;
        if (!path) return item; // No path to filter
        const decision = await this.evaluateFile(path, settings, "GET");
        return decision.allowed ? item : null;
      }),
    );
    return filtered.filter((item) => item !== null);
  }
}
