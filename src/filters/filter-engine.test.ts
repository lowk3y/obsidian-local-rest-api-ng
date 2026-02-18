import { FilterEngine } from "./filter-engine";
import type { ParsedRules } from "./rules-file";
import { App, TFile, CachedMetadata, Vault } from "../../mocks/obsidian";

function makeEngine(rules?: Partial<ParsedRules>): FilterEngine {
  const app = new App();
  // @ts-ignore - mock App
  const engine = new FilterEngine(app);
  if (rules) {
    engine.fileRules = {
      folder: [],
      name: [],
      tag: [],
      keyword: [],
      ...rules,
    };
  }
  return engine;
}

const defaultSettings = {
  defaultPolicy: "deny" as const,
  globalAllowTag: "#ai-allow",
  globalDenyTag: "#ai-deny",
};

describe("FilterEngine.evaluateFile", () => {
  describe("default policy", () => {
    it("denies when default policy is deny and no rules match", async () => {
      const engine = makeEngine({ folder: [] });
      const result = await engine.evaluateFile(
        "some/file.md",
        defaultSettings,
      );
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Default policy: deny");
    });

    it("allows when default policy is allow and no rules match", async () => {
      const engine = makeEngine({ folder: [] });
      const result = await engine.evaluateFile("some/file.md", {
        ...defaultSettings,
        defaultPolicy: "allow",
      });
      expect(result.allowed).toBe(true);
    });
  });

  describe("folder rules", () => {
    it("allows files matching an allow folder rule", async () => {
      const engine = makeEngine({
        folder: [
          {
            id: "r1",
            mode: "allow",
            pattern: "PAI/**",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
      });
      const result = await engine.evaluateFile(
        "PAI/file.md",
        defaultSettings,
      );
      expect(result.allowed).toBe(true);
    });

    it("denies files matching a deny folder rule", async () => {
      const engine = makeEngine({
        folder: [
          {
            id: "r1",
            mode: "deny",
            pattern: "Private/**",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
      });
      const result = await engine.evaluateFile(
        "Private/secret.md",
        defaultSettings,
      );
      expect(result.allowed).toBe(false);
    });
  });

  describe("name rules", () => {
    it("allows files matching a name pattern", async () => {
      const engine = makeEngine({
        name: [
          {
            id: "r1",
            mode: "allow",
            pattern: "*.md",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
      });
      const result = await engine.evaluateFile(
        "notes/readme.md",
        defaultSettings,
      );
      expect(result.allowed).toBe(true);
    });

    it("denies files matching a deny name pattern", async () => {
      const engine = makeEngine({
        name: [
          {
            id: "r1",
            mode: "deny",
            pattern: "*.tmp",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
      });
      const result = await engine.evaluateFile(
        "scratch/notes.tmp",
        defaultSettings,
      );
      expect(result.allowed).toBe(false);
    });
  });

  describe("evaluation order — folder before name", () => {
    it("folder rule takes precedence over name rule", async () => {
      const engine = makeEngine({
        folder: [
          {
            id: "r1",
            mode: "deny",
            pattern: "Private/**",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
        name: [
          {
            id: "r2",
            mode: "allow",
            pattern: "*.md",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
      });
      const result = await engine.evaluateFile(
        "Private/notes.md",
        defaultSettings,
      );
      // Folder deny fires first, even though name would allow
      expect(result.allowed).toBe(false);
    });
  });

  describe("method filtering", () => {
    it("skips rule when method does not match", async () => {
      const engine = makeEngine({
        folder: [
          {
            id: "r1",
            mode: "allow",
            pattern: "PAI/**",
            isRegex: false,
            enabled: true,
            description: "test",
            methods: ["GET"],
          },
        ],
      });
      // PUT method doesn't match the GET-only rule
      const result = await engine.evaluateFile(
        "PAI/file.md",
        defaultSettings,
        "PUT",
      );
      // Falls through to default deny
      expect(result.allowed).toBe(false);
    });

    it("applies rule when method matches", async () => {
      const engine = makeEngine({
        folder: [
          {
            id: "r1",
            mode: "allow",
            pattern: "PAI/**",
            isRegex: false,
            enabled: true,
            description: "test",
            methods: ["GET"],
          },
        ],
      });
      const result = await engine.evaluateFile(
        "PAI/file.md",
        defaultSettings,
        "GET",
      );
      expect(result.allowed).toBe(true);
    });

    it("applies rule when no method restriction set", async () => {
      const engine = makeEngine({
        folder: [
          {
            id: "r1",
            mode: "allow",
            pattern: "PAI/**",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
      });
      const result = await engine.evaluateFile(
        "PAI/file.md",
        defaultSettings,
        "DELETE",
      );
      expect(result.allowed).toBe(true);
    });
  });

  describe("global tag priority — overrides folder and name rules", () => {
    it("ai-allow overrides folder deny", async () => {
      const app = new App();
      const cache = app.metadataCache._getFileCache!;
      cache.frontmatter = { tags: ["#ai-allow"] };
      // @ts-ignore - mock App
      const engine = new FilterEngine(app);
      engine.fileRules = {
        folder: [
          {
            id: "r1",
            mode: "deny",
            pattern: "Restricted/**",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
        name: [],
        tag: [],
        keyword: [],
      };
      const result = await engine.evaluateFile(
        "Restricted/journal.md",
        defaultSettings,
      );
      expect(result.allowed).toBe(true);
      expect(result.reason).toContain("Global allow tag");
    });

    it("ai-deny overrides folder allow", async () => {
      const app = new App();
      const cache = app.metadataCache._getFileCache!;
      cache.frontmatter = { tags: ["#ai-deny"] };
      // @ts-ignore - mock App
      const engine = new FilterEngine(app);
      engine.fileRules = {
        folder: [
          {
            id: "r1",
            mode: "allow",
            pattern: "Public/**",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
        name: [],
        tag: [],
        keyword: [],
      };
      const result = await engine.evaluateFile(
        "Public/tagged-deny.md",
        defaultSettings,
      );
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Global deny tag");
    });

    it("ai-deny trumps ai-allow when both present", async () => {
      const app = new App();
      const cache = app.metadataCache._getFileCache!;
      cache.frontmatter = { tags: ["#ai-allow", "#ai-deny"] };
      // @ts-ignore - mock App
      const engine = new FilterEngine(app);
      engine.fileRules = { folder: [], name: [], tag: [], keyword: [] };
      const result = await engine.evaluateFile(
        "some/file.md",
        defaultSettings,
      );
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Global deny tag");
    });

    it("ai-allow works even with no custom tag rules", async () => {
      const app = new App();
      const cache = app.metadataCache._getFileCache!;
      cache.frontmatter = { tags: ["#ai-allow"] };
      // @ts-ignore - mock App
      const engine = new FilterEngine(app);
      engine.fileRules = { folder: [], name: [], tag: [], keyword: [] };
      const result = await engine.evaluateFile(
        "tagged-allow.md",
        defaultSettings,
      );
      expect(result.allowed).toBe(true);
      expect(result.reason).toContain("Global allow tag");
    });

    it("ai-allow overrides name deny rule", async () => {
      const app = new App();
      const cache = app.metadataCache._getFileCache!;
      cache.frontmatter = { tags: ["#ai-allow"] };
      // @ts-ignore - mock App
      const engine = new FilterEngine(app);
      engine.fileRules = {
        folder: [],
        name: [
          {
            id: "r1",
            mode: "deny",
            pattern: "draft-*",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
        tag: [],
        keyword: [],
      };
      const result = await engine.evaluateFile(
        "draft-special.md",
        defaultSettings,
      );
      expect(result.allowed).toBe(true);
      expect(result.reason).toContain("Global allow tag");
    });

    it("files without global tags still follow normal chain", async () => {
      const app = new App();
      const cache = app.metadataCache._getFileCache!;
      cache.frontmatter = { tags: ["general"] };
      // @ts-ignore - mock App
      const engine = new FilterEngine(app);
      engine.fileRules = {
        folder: [
          {
            id: "r1",
            mode: "deny",
            pattern: "Restricted/**",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
        name: [],
        tag: [],
        keyword: [],
      };
      const result = await engine.evaluateFile(
        "Restricted/file.md",
        defaultSettings,
      );
      // No global tag → folder deny fires normally
      expect(result.allowed).toBe(false);
    });
  });

  describe("null cache with tag rules", () => {
    it("denies when cache null + global tags configured + default allow", async () => {
      const app = new App();
      app.metadataCache._getFileCache = null;
      // @ts-ignore - mock App
      const engine = new FilterEngine(app);
      engine.fileRules = { folder: [], name: [], tag: [], keyword: [] };
      const result = await engine.evaluateFile("some/file.md", {
        ...defaultSettings,
        defaultPolicy: "allow",
      });
      // Should deny because global tags are configured and cache is null
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Tag cache unavailable");
    });

    it("falls through to default when cache null + no global tags configured", async () => {
      const app = new App();
      app.metadataCache._getFileCache = null;
      // @ts-ignore - mock App
      const engine = new FilterEngine(app);
      engine.fileRules = { folder: [], name: [], tag: [], keyword: [] };
      const result = await engine.evaluateFile("some/file.md", {
        defaultPolicy: "allow",
        globalAllowTag: "",
        globalDenyTag: "",
      });
      // No tags configured → null cache doesn't trigger deny → falls to default allow
      expect(result.allowed).toBe(true);
      expect(result.reason).toContain("Default policy: allow");
    });

    it("denies when cache null + custom tag rules + default allow", async () => {
      const app = new App();
      app.metadataCache._getFileCache = null;
      // @ts-ignore - mock App
      const engine = new FilterEngine(app);
      engine.fileRules = {
        folder: [],
        name: [],
        tag: [
          {
            id: "r1",
            mode: "allow",
            pattern: "#public",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
        keyword: [],
      };
      const result = await engine.evaluateFile("some/file.md", {
        defaultPolicy: "allow",
        globalAllowTag: "",
        globalDenyTag: "",
      });
      // Custom tag rules exist, cache is null → deny
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Tag cache unavailable");
    });

    it("folder rules still work when cache is null", async () => {
      const app = new App();
      app.metadataCache._getFileCache = null;
      // @ts-ignore - mock App
      const engine = new FilterEngine(app);
      engine.fileRules = {
        folder: [
          {
            id: "r1",
            mode: "allow",
            pattern: "Public/**",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
        name: [],
        tag: [],
        keyword: [],
      };
      const result = await engine.evaluateFile("Public/note.md", {
        defaultPolicy: "deny",
        globalAllowTag: "",
        globalDenyTag: "",
      });
      // Folder rule matches before tags are checked → allowed
      expect(result.allowed).toBe(true);
    });

    it("filterPaths correctly filters when some files have null cache", async () => {
      const app = new App();
      app.metadataCache._getFileCache = null;
      // @ts-ignore - mock App
      const engine = new FilterEngine(app);
      engine.fileRules = {
        folder: [
          {
            id: "r1",
            mode: "allow",
            pattern: "Public/**",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
        name: [],
        tag: [],
        keyword: [],
      };
      const paths = ["Public/a.md", "Private/b.md"];
      const filtered = await engine.filterPaths(paths, {
        ...defaultSettings,
        globalAllowTag: "",
        globalDenyTag: "",
      });
      // Public/a.md matches folder allow, Private/b.md falls to default deny
      expect(filtered).toEqual(["Public/a.md"]);
    });
  });

  describe("no rules loaded (fileRules is null)", () => {
    it("falls through to default policy", async () => {
      const engine = makeEngine(); // no rules
      const result = await engine.evaluateFile(
        "any/file.md",
        defaultSettings,
      );
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Default policy");
    });
  });

  describe("filterPaths", () => {
    it("filters array of paths, returning only allowed ones", async () => {
      const engine = makeEngine({
        folder: [
          {
            id: "r1",
            mode: "allow",
            pattern: "PAI/**",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
      });
      const paths = [
        "PAI/file1.md",
        "Other/file2.md",
        "PAI/sub/file3.md",
      ];
      const filtered = await engine.filterPaths(paths, defaultSettings);
      expect(filtered).toEqual(["PAI/file1.md", "PAI/sub/file3.md"]);
    });
  });

  describe("filterSearchResults", () => {
    it("strips denied files from search results", async () => {
      const engine = makeEngine({
        folder: [
          {
            id: "r1",
            mode: "allow",
            pattern: "PAI/**",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
      });
      const results = [
        { filename: "PAI/note.md", score: 1 },
        { filename: "Private/secret.md", score: 2 },
        { filename: "PAI/other.md", score: 3 },
      ];
      const filtered = await engine.filterSearchResults(
        results,
        defaultSettings,
      );
      expect(filtered).toHaveLength(2);
      expect(filtered.map((r: any) => r.filename)).toEqual([
        "PAI/note.md",
        "PAI/other.md",
      ]);
    });
  });
});
