import { parseRulesFile, serializeRule, generateDefaultRulesFile } from "./rules-file";
import type { FilterRule } from "./types";

describe("parseRulesFile", () => {
  describe("basic parsing", () => {
    it("parses a simple allow folder rule", () => {
      const { grouped, entries } = parseRulesFile("allow folder PAI/**");
      expect(grouped.folder).toHaveLength(1);
      expect(grouped.folder[0].mode).toBe("allow");
      expect(grouped.folder[0].pattern).toBe("PAI/**");
      expect(grouped.folder[0].enabled).toBe(true);
      expect(entries).toHaveLength(1);
      expect(entries[0].filterType).toBe("folder");
    });

    it("parses a deny name rule", () => {
      const { grouped } = parseRulesFile("deny name *.tmp");
      expect(grouped.name).toHaveLength(1);
      expect(grouped.name[0].mode).toBe("deny");
      expect(grouped.name[0].pattern).toBe("*.tmp");
    });

    it("parses a tag rule", () => {
      const { grouped } = parseRulesFile("deny tag #secret");
      expect(grouped.tag).toHaveLength(1);
      expect(grouped.tag[0].pattern).toBe("#secret");
    });

    it("parses a keyword rule", () => {
      const { grouped } = parseRulesFile("deny keyword password");
      expect(grouped.keyword).toHaveLength(1);
      expect(grouped.keyword[0].pattern).toBe("password");
    });
  });

  describe("multiple rules", () => {
    it("parses multiple rules into correct groups", () => {
      const content = [
        "allow folder PAI/**",
        "deny folder Private/**",
        "allow name *.md",
        "deny tag #secret",
      ].join("\n");

      const { grouped, entries } = parseRulesFile(content);
      expect(grouped.folder).toHaveLength(2);
      expect(grouped.name).toHaveLength(1);
      expect(grouped.tag).toHaveLength(1);
      expect(grouped.keyword).toHaveLength(0);
      expect(entries).toHaveLength(4);
    });
  });

  describe("comments and whitespace", () => {
    it("skips comment lines", () => {
      const content = [
        "# This is a comment",
        "allow folder PAI/**",
        "# Another comment",
      ].join("\n");

      const { grouped } = parseRulesFile(content);
      expect(grouped.folder).toHaveLength(1);
    });

    it("skips empty lines", () => {
      const content = [
        "",
        "allow folder PAI/**",
        "",
        "",
        "deny folder Private/**",
        "",
      ].join("\n");

      const { grouped } = parseRulesFile(content);
      expect(grouped.folder).toHaveLength(2);
    });

    it("handles empty file", () => {
      const { grouped, entries } = parseRulesFile("");
      expect(grouped.folder).toHaveLength(0);
      expect(grouped.name).toHaveLength(0);
      expect(grouped.tag).toHaveLength(0);
      expect(grouped.keyword).toHaveLength(0);
      expect(entries).toHaveLength(0);
    });
  });

  describe("disabled rules (#!disabled)", () => {
    it("parses disabled rules with enabled=false", () => {
      const { grouped, entries } = parseRulesFile(
        "#!disabled allow folder Archive/**",
      );
      // Disabled rules appear in entries but NOT in grouped (used by engine)
      expect(entries).toHaveLength(1);
      expect(entries[0].rule.enabled).toBe(false);
      expect(entries[0].rule.mode).toBe("allow");
      expect(entries[0].rule.pattern).toBe("Archive/**");
      expect(grouped.folder).toHaveLength(0); // Not in active rules
    });

    it("distinguishes disabled rules from regular comments", () => {
      const content = [
        "# regular comment",
        "#!disabled allow folder Archive/**",
        "allow folder PAI/**",
      ].join("\n");

      const { grouped, entries } = parseRulesFile(content);
      expect(entries).toHaveLength(2); // disabled + active
      expect(grouped.folder).toHaveLength(1); // only active
    });
  });

  describe("regex patterns", () => {
    it("detects regex patterns with ~ prefix", () => {
      const { grouped } = parseRulesFile(
        "allow folder ~^(PAI|Projects)/",
      );
      expect(grouped.folder).toHaveLength(1);
      expect(grouped.folder[0].isRegex).toBe(true);
      expect(grouped.folder[0].pattern).toBe("^(PAI|Projects)/");
    });

    it("non-regex patterns have isRegex=false", () => {
      const { grouped } = parseRulesFile("allow folder PAI/**");
      expect(grouped.folder[0].isRegex).toBe(false);
    });

    it("extracts /i flag from regex pattern", () => {
      const { grouped } = parseRulesFile("deny keyword ~password/i");
      expect(grouped.keyword).toHaveLength(1);
      expect(grouped.keyword[0].isRegex).toBe(true);
      expect(grouped.keyword[0].pattern).toBe("password");
      expect(grouped.keyword[0].regexFlags).toBe("i");
    });

    it("extracts /gi flags from regex pattern", () => {
      const { grouped } = parseRulesFile("deny keyword ~password/gi");
      expect(grouped.keyword[0].regexFlags).toBe("gi");
      expect(grouped.keyword[0].pattern).toBe("password");
    });

    it("does not extract flags from non-regex patterns", () => {
      const { grouped } = parseRulesFile("deny keyword password/i");
      expect(grouped.keyword[0].isRegex).toBe(false);
      expect(grouped.keyword[0].pattern).toBe("password/i");
      expect(grouped.keyword[0].regexFlags).toBeUndefined();
    });

    it("regex without flags has undefined regexFlags", () => {
      const { grouped } = parseRulesFile("deny keyword ~password");
      expect(grouped.keyword[0].isRegex).toBe(true);
      expect(grouped.keyword[0].regexFlags).toBeUndefined();
    });
  });

  describe("HTTP methods", () => {
    it("parses comma-separated methods", () => {
      const { grouped } = parseRulesFile(
        "deny keyword password GET,POST",
      );
      expect(grouped.keyword[0].methods).toEqual(["GET", "POST"]);
    });

    it("normalizes methods to uppercase", () => {
      const { grouped } = parseRulesFile(
        "deny folder Private/** get,post",
      );
      expect(grouped.folder[0].methods).toEqual(["GET", "POST"]);
    });

    it("omits methods when not specified", () => {
      const { grouped } = parseRulesFile("allow folder PAI/**");
      expect(grouped.folder[0].methods).toBeUndefined();
    });

    it("filters invalid methods", () => {
      const { grouped } = parseRulesFile(
        "deny folder Private/** GET,INVALID,POST",
      );
      expect(grouped.folder[0].methods).toEqual(["GET", "POST"]);
    });
  });

  describe("line number tracking", () => {
    it("tracks correct line numbers including skipped lines", () => {
      const content = [
        "# comment",          // line 0
        "",                   // line 1
        "allow folder PAI/**", // line 2
        "# another comment",  // line 3
        "deny folder Private/**", // line 4
      ].join("\n");

      const { entries } = parseRulesFile(content);
      expect(entries).toHaveLength(2);
      expect(entries[0].lineNumber).toBe(2);
      expect(entries[1].lineNumber).toBe(4);
    });
  });

  describe("quoted patterns (spaces in names)", () => {
    it("parses a quoted folder pattern with spaces", () => {
      const { grouped } = parseRulesFile('allow folder "00 Workpad/**"');
      expect(grouped.folder).toHaveLength(1);
      expect(grouped.folder[0].mode).toBe("allow");
      expect(grouped.folder[0].pattern).toBe("00 Workpad/**");
      expect(grouped.folder[0].isRegex).toBe(false);
    });

    it("parses a quoted pattern with methods", () => {
      const { grouped } = parseRulesFile(
        'allow folder "My Documents/**" GET,POST',
      );
      expect(grouped.folder).toHaveLength(1);
      expect(grouped.folder[0].pattern).toBe("My Documents/**");
      expect(grouped.folder[0].methods).toEqual(["GET", "POST"]);
    });

    it("parses a disabled quoted pattern", () => {
      const { entries, grouped } = parseRulesFile(
        '#!disabled deny folder "00 Workpad/**"',
      );
      expect(entries).toHaveLength(1);
      expect(entries[0].rule.enabled).toBe(false);
      expect(entries[0].rule.pattern).toBe("00 Workpad/**");
      expect(grouped.folder).toHaveLength(0);
    });

    it("rejects unterminated quoted pattern", () => {
      const spy = jest.spyOn(console, "warn").mockImplementation();
      const { grouped } = parseRulesFile('allow folder "00 Workpad/**');
      expect(grouped.folder).toHaveLength(0);
      spy.mockRestore();
    });

    it("handles quoted pattern with multiple spaces", () => {
      const { grouped } = parseRulesFile(
        'deny folder "My Long Folder Name/**"',
      );
      expect(grouped.folder).toHaveLength(1);
      expect(grouped.folder[0].pattern).toBe("My Long Folder Name/**");
    });
  });

  describe("invalid lines", () => {
    it("skips lines with fewer than 3 fields", () => {
      const spy = jest.spyOn(console, "warn").mockImplementation();
      const { grouped } = parseRulesFile("allow folder");
      expect(grouped.folder).toHaveLength(0);
      spy.mockRestore();
    });

    it("skips lines with invalid mode", () => {
      const spy = jest.spyOn(console, "warn").mockImplementation();
      const { grouped } = parseRulesFile("permit folder PAI/**");
      expect(grouped.folder).toHaveLength(0);
      spy.mockRestore();
    });

    it("skips lines with invalid filter type", () => {
      const spy = jest.spyOn(console, "warn").mockImplementation();
      const { grouped } = parseRulesFile("allow path PAI/**");
      expect(grouped.folder).toHaveLength(0);
      spy.mockRestore();
    });
  });
});

describe("serializeRule", () => {
  it("serializes a basic allow rule", () => {
    const rule: FilterRule = {
      id: "r1",
      mode: "allow",
      pattern: "PAI/**",
      isRegex: false,
      enabled: true,
      description: "",
    };
    expect(serializeRule("folder", rule)).toBe("allow  folder  PAI/**");
  });

  it("serializes a disabled rule with #!disabled prefix", () => {
    const rule: FilterRule = {
      id: "r1",
      mode: "deny",
      pattern: "Private/**",
      isRegex: false,
      enabled: false,
      description: "",
    };
    expect(serializeRule("folder", rule)).toBe(
      "#!disabled deny  folder  Private/**",
    );
  });

  it("serializes regex pattern with ~ prefix", () => {
    const rule: FilterRule = {
      id: "r1",
      mode: "allow",
      pattern: "^(PAI|Projects)/",
      isRegex: true,
      enabled: true,
      description: "",
    };
    expect(serializeRule("folder", rule)).toBe(
      "allow  folder  ~^(PAI|Projects)/",
    );
  });

  it("serializes regex pattern with /i flag", () => {
    const rule: FilterRule = {
      id: "r1",
      mode: "deny",
      pattern: "password",
      isRegex: true,
      enabled: true,
      description: "",
      regexFlags: "i",
    };
    expect(serializeRule("keyword", rule)).toBe("deny  keyword  ~password/i");
  });

  it("roundtrips a regex /i pattern through serialize/parse", () => {
    const rule: FilterRule = {
      id: "r1",
      mode: "deny",
      pattern: "password",
      isRegex: true,
      enabled: true,
      description: "",
      regexFlags: "i",
    };
    const serialized = serializeRule("keyword", rule);
    const { grouped } = parseRulesFile(serialized);
    expect(grouped.keyword).toHaveLength(1);
    expect(grouped.keyword[0].pattern).toBe("password");
    expect(grouped.keyword[0].regexFlags).toBe("i");
    expect(grouped.keyword[0].isRegex).toBe(true);
  });

  it("quotes patterns containing spaces", () => {
    const rule: FilterRule = {
      id: "r1",
      mode: "allow",
      pattern: "00 Workpad/**",
      isRegex: false,
      enabled: true,
      description: "",
    };
    expect(serializeRule("folder", rule)).toBe(
      'allow  folder  "00 Workpad/**"',
    );
  });

  it("roundtrips a space-containing pattern through serialize/parse", () => {
    const rule: FilterRule = {
      id: "r1",
      mode: "allow",
      pattern: "00 Workpad/**",
      isRegex: false,
      enabled: true,
      description: "",
    };
    const serialized = serializeRule("folder", rule);
    const { grouped } = parseRulesFile(serialized);
    expect(grouped.folder).toHaveLength(1);
    expect(grouped.folder[0].pattern).toBe("00 Workpad/**");
    expect(grouped.folder[0].mode).toBe("allow");
  });

  it("serializes methods", () => {
    const rule: FilterRule = {
      id: "r1",
      mode: "deny",
      pattern: "password",
      isRegex: false,
      enabled: true,
      description: "",
      methods: ["GET", "POST"],
    };
    expect(serializeRule("keyword", rule)).toBe(
      "deny  keyword  password  GET,POST",
    );
  });
});

describe("generateDefaultRulesFile", () => {
  it("returns a non-empty template", () => {
    const template = generateDefaultRulesFile();
    expect(template.length).toBeGreaterThan(0);
  });

  it("parses to zero active rules", () => {
    const template = generateDefaultRulesFile();
    const { grouped, entries } = parseRulesFile(template);
    expect(grouped.folder).toHaveLength(0);
    expect(entries).toHaveLength(0);
  });
});
