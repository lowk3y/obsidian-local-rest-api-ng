/** Filter rule mode */
export type FilterMode = "deny" | "allow";

/** Filter type identifiers */
export type FilterType = "folder" | "document-name" | "tag" | "keyword";

/** HTTP methods that can be filtered */
export type HttpMethod = "GET" | "PUT" | "POST" | "PATCH" | "DELETE";

/** A single configurable filter rule */
export interface FilterRule {
  id: string;
  mode: FilterMode;
  pattern: string;
  isRegex: boolean;
  enabled: boolean;
  description: string;
  /** If set, rule only applies to these HTTP methods. Empty/undefined = all methods */
  methods?: HttpMethod[];
  /** Regex flags extracted from pattern suffix (e.g., "i" from ~pattern/i) */
  regexFlags?: string;
}

/** Result of evaluating a file against the filter engine */
export interface FilterDecision {
  allowed: boolean;
  reason: string;
  matchedRule?: FilterRule;
  filterType?: FilterType;
}

/** Configuration for a single filter type */
export interface FilterConfig {
  enabled: boolean;
  rules: FilterRule[];
}

/** Security filter settings — merged into LocalRestApiSettings */
export interface SecurityFilterSettings {
  securityFilterEnabled: boolean;
  defaultPolicy: FilterMode;
  readOnlyMode: boolean;
  globalAllowTag: string;
  globalDenyTag: string;
  folderFilter: FilterConfig;
  documentNameFilter: FilterConfig;
  tagFilter: FilterConfig;
  keywordFilter: FilterConfig;
}
