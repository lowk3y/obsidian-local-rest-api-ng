import { checkGlobalTags, checkTagFilter } from "./tag-filter";
import { App, TFile, CachedMetadata, Vault, MetadataCache } from "../../mocks/obsidian";

describe("checkGlobalTags", () => {
  it("denies when cache null and global deny tag configured", () => {
    const app = new App();
    // File exists but cache is null
    app.metadataCache._getFileCache = null;

    const result = checkGlobalTags(
      "some/file.md",
      app.metadataCache,
      app.vault,
      "",
      "#ai-deny",
    );

    expect(result).not.toBeNull();
    expect(result!.allowed).toBe(false);
    expect(result!.reason).toContain("Tag cache unavailable");
    expect(result!.filterType).toBe("tag");
  });

  it("denies when cache null and global allow tag configured", () => {
    const app = new App();
    app.metadataCache._getFileCache = null;

    const result = checkGlobalTags(
      "some/file.md",
      app.metadataCache,
      app.vault,
      "#ai-allow",
      "",
    );

    expect(result).not.toBeNull();
    expect(result!.allowed).toBe(false);
    expect(result!.reason).toContain("Tag cache unavailable");
  });

  it("denies when cache null and both global tags configured", () => {
    const app = new App();
    app.metadataCache._getFileCache = null;

    const result = checkGlobalTags(
      "some/file.md",
      app.metadataCache,
      app.vault,
      "#ai-allow",
      "#ai-deny",
    );

    expect(result).not.toBeNull();
    expect(result!.allowed).toBe(false);
  });

  it("returns null when cache null and no global tags configured", () => {
    const app = new App();
    app.metadataCache._getFileCache = null;

    const result = checkGlobalTags(
      "some/file.md",
      app.metadataCache,
      app.vault,
      "",
      "",
    );

    expect(result).toBeNull();
  });

  it("returns null when vault file not found (e.g. POST creating new file)", () => {
    const app = new App();
    app.vault._getAbstractFileByPath = null;

    const result = checkGlobalTags(
      "nonexistent/file.md",
      app.metadataCache,
      app.vault,
      "#ai-allow",
      "#ai-deny",
    );

    // File doesn't exist → no opinion, let folder/name rules decide
    expect(result).toBeNull();
  });

  it("denies when file has global deny tag", () => {
    const app = new App();
    app.metadataCache._getFileCache = new CachedMetadata();
    app.metadataCache._getFileCache.frontmatter = { tags: ["#ai-deny"] };

    const result = checkGlobalTags(
      "some/file.md",
      app.metadataCache,
      app.vault,
      "#ai-allow",
      "#ai-deny",
    );

    expect(result).not.toBeNull();
    expect(result!.allowed).toBe(false);
    expect(result!.reason).toContain("Global deny tag");
  });

  it("allows when file has global allow tag", () => {
    const app = new App();
    app.metadataCache._getFileCache = new CachedMetadata();
    app.metadataCache._getFileCache.frontmatter = { tags: ["#ai-allow"] };

    const result = checkGlobalTags(
      "some/file.md",
      app.metadataCache,
      app.vault,
      "#ai-allow",
      "#ai-deny",
    );

    expect(result).not.toBeNull();
    expect(result!.allowed).toBe(true);
    expect(result!.reason).toContain("Global allow tag");
  });

  it("returns null when cache available but no global tags match", () => {
    const app = new App();
    app.metadataCache._getFileCache = new CachedMetadata();
    app.metadataCache._getFileCache.frontmatter = { tags: ["#other-tag"] };

    const result = checkGlobalTags(
      "some/file.md",
      app.metadataCache,
      app.vault,
      "#ai-allow",
      "#ai-deny",
    );

    expect(result).toBeNull();
  });
});

describe("checkTagFilter", () => {
  it("denies when cache null and tag rules exist", () => {
    const app = new App();
    app.metadataCache._getFileCache = null;

    const result = checkTagFilter(
      "some/file.md",
      [
        {
          id: "r1",
          mode: "allow",
          pattern: "#public",
          isRegex: false,
          enabled: true,
          description: "test",
        },
      ],
      app.metadataCache,
      app.vault,
    );

    expect(result).not.toBeNull();
    expect(result!.allowed).toBe(false);
    expect(result!.reason).toContain("Tag cache unavailable");
    expect(result!.filterType).toBe("tag");
  });

  it("returns null when vault file not found (e.g. POST creating new file)", () => {
    const app = new App();
    app.vault._getAbstractFileByPath = null;

    const result = checkTagFilter(
      "nonexistent/file.md",
      [
        {
          id: "r1",
          mode: "allow",
          pattern: "#public",
          isRegex: false,
          enabled: true,
          description: "test",
        },
      ],
      app.metadataCache,
      app.vault,
    );

    // File doesn't exist → no opinion, let other filters decide
    expect(result).toBeNull();
  });

  it("allows when tag matches allow rule", () => {
    const app = new App();
    app.metadataCache._getFileCache = new CachedMetadata();
    app.metadataCache._getFileCache.tags = [{ tag: "#public" }];

    const result = checkTagFilter(
      "some/file.md",
      [
        {
          id: "r1",
          mode: "allow",
          pattern: "#public",
          isRegex: false,
          enabled: true,
          description: "test",
        },
      ],
      app.metadataCache,
      app.vault,
    );

    expect(result).not.toBeNull();
    expect(result!.allowed).toBe(true);
  });

  it("denies when tag matches deny rule", () => {
    const app = new App();
    app.metadataCache._getFileCache = new CachedMetadata();
    app.metadataCache._getFileCache.tags = [{ tag: "#private" }];

    const result = checkTagFilter(
      "some/file.md",
      [
        {
          id: "r1",
          mode: "deny",
          pattern: "#private",
          isRegex: false,
          enabled: true,
          description: "test",
        },
      ],
      app.metadataCache,
      app.vault,
    );

    expect(result).not.toBeNull();
    expect(result!.allowed).toBe(false);
  });

  it("returns null when cache available but no tag rules match", () => {
    const app = new App();
    app.metadataCache._getFileCache = new CachedMetadata();
    app.metadataCache._getFileCache.tags = [{ tag: "#unrelated" }];

    const result = checkTagFilter(
      "some/file.md",
      [
        {
          id: "r1",
          mode: "allow",
          pattern: "#public",
          isRegex: false,
          enabled: true,
          description: "test",
        },
      ],
      app.metadataCache,
      app.vault,
    );

    expect(result).toBeNull();
  });

  describe("compound AND tag matching", () => {
    it("denies when all compound tags are present", () => {
      const app = new App();
      app.metadataCache._getFileCache = new CachedMetadata();
      app.metadataCache._getFileCache.tags = [
        { tag: "#draft" },
        { tag: "#internal" },
      ];

      const result = checkTagFilter(
        "some/file.md",
        [
          {
            id: "r1",
            mode: "deny",
            pattern: "#draft+#internal",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
        app.metadataCache,
        app.vault,
      );

      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });

    it("does not match when only one compound tag is present", () => {
      const app = new App();
      app.metadataCache._getFileCache = new CachedMetadata();
      app.metadataCache._getFileCache.tags = [{ tag: "#draft" }];

      const result = checkTagFilter(
        "some/file.md",
        [
          {
            id: "r1",
            mode: "deny",
            pattern: "#draft+#internal",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
        app.metadataCache,
        app.vault,
      );

      expect(result).toBeNull();
    });

    it("matches compound tags from frontmatter and inline", () => {
      const app = new App();
      app.metadataCache._getFileCache = new CachedMetadata();
      app.metadataCache._getFileCache.tags = [{ tag: "#draft" }];
      app.metadataCache._getFileCache.frontmatter = { tags: ["internal"] };

      const result = checkTagFilter(
        "some/file.md",
        [
          {
            id: "r1",
            mode: "deny",
            pattern: "#draft+#internal",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
        app.metadataCache,
        app.vault,
      );

      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });

    it("handles three-tag compound rule", () => {
      const app = new App();
      app.metadataCache._getFileCache = new CachedMetadata();
      app.metadataCache._getFileCache.tags = [
        { tag: "#draft" },
        { tag: "#internal" },
        { tag: "#sensitive" },
      ];

      const result = checkTagFilter(
        "some/file.md",
        [
          {
            id: "r1",
            mode: "deny",
            pattern: "#draft+#internal+#sensitive",
            isRegex: false,
            enabled: true,
            description: "test",
          },
        ],
        app.metadataCache,
        app.vault,
      );

      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });
  });
});
