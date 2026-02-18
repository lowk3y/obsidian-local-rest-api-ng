import { App, Modal, Plugin, PluginSettingTab, Setting } from "obsidian";
import * as https from "https";
import * as http from "http";
import forge, { pki } from "node-forge";

import RequestHandler from "./requestHandler";
import { LocalRestApiSettings } from "./types";
import type { FilterRule, FilterMode, HttpMethod } from "./filters/types";
import type { RuleEntry } from "./filters/rules-file";
import { FilterEngine } from "./filters/filter-engine";
import {
  loadRulesFile,
  generateDefaultRulesFile,
  appendRule,
  removeRuleByLine,
  toggleRuleByLine,
} from "./filters/rules-file";
import { AuditLogger } from "./audit/audit-logger";
import { createSecurityFilterMiddleware } from "./securityFilterMiddleware";

import {
  DefaultBearerTokenHeaderName,
  CERT_NAME,
  DEFAULT_SETTINGS,
  DefaultBindingHost,
  LicenseUrl,
  SECURITY_FILTER_DEFAULTS,
} from "./constants";
import {
  getCertificateIsUptoStandards,
  getCertificateValidityDays,
} from "./utils";
import LocalRestApiPublicApi from "./api";
import { PluginManifest } from "obsidian";

export default class LocalRestApi extends Plugin {
  settings: LocalRestApiSettings;
  secureServer: https.Server | null = null;
  insecureServer: http.Server | null = null;
  requestHandler: RequestHandler;
  refreshServerState: () => void;
  auditLogger: AuditLogger | null = null;
  filterEngine: FilterEngine | null = null;
  pluginDir: string = "";

  async onload() {
    this.refreshServerState = this.debounce(
      this._refreshServerState.bind(this),
      1000
    );

    await this.loadSettings();

    // Initialize security filtering BEFORE setupRouter so middleware is registered
    const filterEngine = new FilterEngine(this.app);
    this.filterEngine = filterEngine;
    // Plugin directory path (vault-relative) for log files and rules
    const pluginDir = `${this.app.vault.configDir}/plugins/${this.manifest.id}`;
    this.pluginDir = pluginDir;

    // Load access-rules.conf (create default template if it doesn't exist)
    const rulesPath = `${pluginDir}/access-rules.conf`;
    const rulesFileExists = await this.app.vault.adapter.exists(rulesPath);
    if (!rulesFileExists) {
      // Migrate old JSON-based filter rules to the new conf file format
      const migrated = this.migrateJsonRulesToConf();
      const template = generateDefaultRulesFile();
      await this.app.vault.adapter.write(
        rulesPath,
        migrated ? `${template}${migrated}\n` : template,
      );
      if (migrated) {
        console.log("[REST API] Migrated filter rules from settings to access-rules.conf");
      } else {
        console.log("[REST API] Created default access-rules.conf template");
      }
    }
    const result = await loadRulesFile(this.app.vault.adapter, pluginDir);
    if (result) {
      filterEngine.fileRules = result.grouped;
    }

    const auditLogger = new AuditLogger(
      this.app.vault.adapter,
      pluginDir,
    );
    this.auditLogger = auditLogger;

    this.requestHandler = new RequestHandler(
      this.app,
      this.manifest,
      this.settings
    );
    this.requestHandler.auditLogger = auditLogger;
    this.requestHandler.filterEngine = filterEngine;
    this.requestHandler.securityFilterMiddleware =
      createSecurityFilterMiddleware(
        this.app,
        () => this.settings,
        filterEngine,
        auditLogger,
      );
    this.requestHandler.setupRouter();

    if (!this.settings.apiKey) {
      this.settings.apiKey = forge.md.sha256
        .create()
        .update(forge.random.getBytesSync(128))
        .digest()
        .toHex();
      this.saveSettings();
    }
    if (!this.settings.crypto) {
      const expiry = new Date();
      const today = new Date();
      expiry.setDate(today.getDate() + 365);

      const keypair = forge.pki.rsa.generateKeyPair(2048);
      const attrs = [
        {
          name: "commonName",
          value: "Obsidian Local REST API NG",
        },
      ];
      const certificate = forge.pki.createCertificate();
      certificate.setIssuer(attrs);
      certificate.setSubject(attrs);

      const subjectAltNames: Record<string, any>[] = [
        {
          type: 7, // IP
          ip: DefaultBindingHost,
        },
      ];
      if (
        this.settings.bindingHost &&
        this.settings.bindingHost !== "0.0.0.0"
      ) {
        subjectAltNames.push({
          type: 7, // IP
          ip: this.settings.bindingHost,
        });
      }
      if (this.settings.subjectAltNames) {
        for (const name of this.settings.subjectAltNames.split("\n")) {
          if (name.trim()) {
            subjectAltNames.push({
              type: 2,
              value: name.trim(),
            });
          }
        }
      }

      certificate.setExtensions([
        {
          name: "basicConstraints",
          cA: true,
          critical: true,
        },
        {
          name: "keyUsage",
          keyCertSign: true,
          digitalSignature: true,
          nonRepudiation: true,
          keyEncipherment: false,
          dataEncipherment: false,
          critical: true,
        },
        {
          name: "extKeyUsage",
          serverAuth: true,
          clientAuth: true,
          codeSigning: true,
          emailProtection: true,
          timeStamping: true,
        },
        {
          name: "nsCertType",
          client: true,
          server: true,
          email: true,
          objsign: true,
          sslCA: true,
          emailCA: true,
          objCA: true,
        },
        {
          name: "subjectAltName",
          altNames: subjectAltNames,
        },
      ]);
      certificate.serialNumber = "1";
      certificate.publicKey = keypair.publicKey;
      certificate.validity.notAfter = expiry;
      certificate.validity.notBefore = today;
      certificate.sign(keypair.privateKey, forge.md.sha256.create());

      this.settings.crypto = {
        cert: pki.certificateToPem(certificate),
        privateKey: pki.privateKeyToPem(keypair.privateKey),
        publicKey: pki.publicKeyToPem(keypair.publicKey),
      };
      this.saveSettings();
    }

    this.addSettingTab(new LocalRestApiSettingTab(this.app, this));

    this.refreshServerState();

    this.app.workspace.trigger("obsidian-local-rest-api:loaded");
  }

  getPublicApi(pluginManifest: PluginManifest): LocalRestApiPublicApi {
    if (!pluginManifest.id || !pluginManifest.name || !pluginManifest.version) {
      throw new Error(
        "PluginManifest instance must include a defined id, name, and version to be accempted."
      );
    }

    console.log("[REST API] Added new API extension", pluginManifest);

    return this.requestHandler.registerApiExtension(pluginManifest);
  }

  debounce<F extends (...args: any[]) => any>(
    func: F,
    delay: number
  ): (...args: Parameters<F>) => void {
    let debounceTimer: NodeJS.Timeout;
    return (...args: Parameters<F>): void => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => func(...args), delay);
    };
  }

  _refreshServerState() {
    if (this.secureServer) {
      this.secureServer.close();
      this.secureServer = null;
    }
    if (this.settings.enableSecureServer ?? true) {
      this.secureServer = https.createServer(
        {
          key: this.settings.crypto.privateKey,
          cert: this.settings.crypto.cert,
        },
        this.requestHandler.api
      );
      this.secureServer.listen(
        this.settings.port,
        this.settings.bindingHost ?? DefaultBindingHost
      );

      console.log(
        `[REST API] Listening on https://${
          this.settings.bindingHost ?? DefaultBindingHost
        }:${this.settings.port}/`
      );
    }

    if (this.insecureServer) {
      this.insecureServer.close();
      this.insecureServer = null;
    }
    if (this.settings.enableInsecureServer) {
      this.insecureServer = http.createServer(this.requestHandler.api);
      this.insecureServer.listen(
        this.settings.insecurePort,
        this.settings.bindingHost ?? DefaultBindingHost
      );

      console.log(
        `[REST API] Listening on http://${
          this.settings.bindingHost ?? DefaultBindingHost
        }:${this.settings.insecurePort}/`
      );
    }
  }

  async onunload() {
    if (this.auditLogger) {
      await this.auditLogger.destroy();
    }
    if (this.secureServer) {
      this.secureServer.close();
    }
    if (this.insecureServer) {
      this.insecureServer.close();
    }
  }

  /**
   * One-time migration: extract filter rules from old JSON settings (data.json)
   * and serialize them into access-rules.conf format.
   * Returns the serialized rules string, or null if no rules to migrate.
   */
  private migrateJsonRulesToConf(): string | null {
    const data = this.settings as any;
    const lines: string[] = [];

    const FILTER_KEYS: { key: string; type: string }[] = [
      { key: "folderFilter", type: "folder" },
      { key: "documentNameFilter", type: "name" },
      { key: "tagFilter", type: "tag" },
      { key: "keywordFilter", type: "keyword" },
    ];

    for (const { key, type } of FILTER_KEYS) {
      const config = data[key];
      if (!config?.rules || !Array.isArray(config.rules)) continue;
      for (const rule of config.rules) {
        if (!rule.pattern) continue;
        const patternStr = rule.isRegex ? `~${rule.pattern}` : rule.pattern;
        const methodStr =
          rule.methods && rule.methods.length > 0
            ? `  ${rule.methods.join(",")}`
            : "";
        const prefix = rule.enabled === false ? "#!disabled " : "";
        lines.push(`${prefix}${rule.mode ?? "allow"}  ${type}  ${patternStr}${methodStr}`);
      }
    }

    if (lines.length === 0) return null;

    // Clean up old settings keys (they're now in conf file)
    for (const { key } of FILTER_KEYS) {
      delete data[key];
    }

    return lines.join("\n");
  }

  async loadSettings() {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
  }

  async saveSettings() {
    await this.saveData(this.settings);
  }
}

class LocalRestApiSettingTab extends PluginSettingTab {
  plugin: LocalRestApi;
  showAdvancedSettings = false;

  constructor(app: App, plugin: LocalRestApi) {
    super(app, plugin);
    this.plugin = plugin;
  }

  async display(): Promise<void> {
    const { containerEl } = this;
    containerEl.replaceChildren();

    if (!this.plugin.settings.crypto?.cert) {
      containerEl.createEl("p", {
        text: "Plugin is initializing. Please close and reopen settings, or restart Obsidian.",
      });
      return;
    }

    const parsedCertificate = forge.pki.certificateFromPem(
      this.plugin.settings.crypto.cert
    );
    const remainingCertificateValidityDays =
      getCertificateValidityDays(parsedCertificate);
    const shouldRegenerateCertificate =
      !getCertificateIsUptoStandards(parsedCertificate);

    containerEl.empty();
    containerEl.classList.add("local-rest-api-ng-settings");
    containerEl.createEl("h2", { text: "Local REST API NG" });
    const forkNote = containerEl.createEl("p");
    forkNote.innerHTML = `Fork of <a href="https://github.com/coddingtonbear/obsidian-local-rest-api">coddingtonbear/obsidian-local-rest-api</a>`;
    containerEl.createEl("h3", { text: "How to Access" });

    const apiKeyDiv = containerEl.createEl("div");
    apiKeyDiv.classList.add("api-key-display");

    const availableApis = apiKeyDiv.createEl("p");
    availableApis.innerHTML = `
      You can access Obsidian Local REST API NG via the following URLs:
    `;

    const connectionUrls = apiKeyDiv.createEl("table", { cls: "api-urls" });
    const connectionUrlsTbody = connectionUrls.createEl("tbody");
    const secureTr = connectionUrlsTbody.createEl(
      "tr",
      this.plugin.settings.enableSecureServer === false
        ? {
            cls: "disabled",
            title: "Disabled.  You can enable this in 'Settings' below.",
          }
        : {
            title: "Enabled",
          }
    );
    const secureUrl = `https://127.0.0.1:${this.plugin.settings.port}/`;
    secureTr.innerHTML = `
          <td>
            ${this.plugin.settings.enableSecureServer === false ? "❌" : "✅"}
          </td>
          <td class="name">
            Encrypted (HTTPS) API URL<br /><br />
            <i>
              Requires that <a href="https://127.0.0.1:${
                this.plugin.settings.port
              }/${CERT_NAME}">this certificate</a> be
              configured as a trusted certificate authority for
              your browser.  See <a href="https://github.com/coddingtonbear/obsidian-web/wiki/How-do-I-get-my-browser-trust-my-Obsidian-Local-REST-API-certificate%3F">wiki</a> for more information.
            </i>
          </td>
      `;
    const secureUrlsTd = secureTr.createEl("td", { cls: "url" });
    secureUrlsTd.innerHTML = `
      ${secureUrl} <a href="javascript:navigator.clipboard.writeText('${secureUrl}')">(copy)</a><br />
    `;
    if (this.plugin.settings.subjectAltNames) {
      for (const name of this.plugin.settings.subjectAltNames.split("\n")) {
        if (name.trim()) {
          const altSecureUrl = `https://${name.trim()}:${
            this.plugin.settings.port
          }/`;
          secureUrlsTd.innerHTML += `
            ${altSecureUrl} <a href="javascript:navigator.clipboard.writeText('${altSecureUrl}')">(copy)</a><br />
          `;
        }
      }
    }

    const insecureTr = connectionUrlsTbody.createEl(
      "tr",
      this.plugin.settings.enableInsecureServer === false
        ? {
            cls: "disabled",
            title: "Disabled.  You can enable this in 'Settings' below.",
          }
        : {
            title: "Enabled",
          }
    );
    const insecureUrl = `http://127.0.0.1:${this.plugin.settings.insecurePort}/`;
    insecureTr.innerHTML = `
        <td>
          ${this.plugin.settings.enableInsecureServer === false ? "❌" : "✅"}
        </td>
        <td class="name">
          Non-encrypted (HTTP) API URL
        </td>
    `;
    const insecureUrlsTd = insecureTr.createEl("td", { cls: "url" });
    insecureUrlsTd.innerHTML = `
      ${insecureUrl} <a href="javascript:navigator.clipboard.writeText('${insecureUrl}')">(copy)</a><br />
    `;
    if (this.plugin.settings.subjectAltNames) {
      for (const name of this.plugin.settings.subjectAltNames.split("\n")) {
        if (name.trim()) {
          const altSecureUrl = `http://${name.trim()}:${
            this.plugin.settings.insecurePort
          }/`;
          insecureUrlsTd.innerHTML += `
            ${altSecureUrl} <a href="javascript:navigator.clipboard.writeText('${altSecureUrl}')">(copy)</a><br />
          `;
        }
      }
    }

    const inOrderToAccess = apiKeyDiv.createEl("p");
    inOrderToAccess.innerHTML = `
      Your API Key must be passed in requests via an authorization header
      <a href="javascript:navigator.clipboard.writeText('${this.plugin.settings.apiKey}')">(copy)</a>:
    `;
    apiKeyDiv.createEl("pre", { text: this.plugin.settings.apiKey });
    apiKeyDiv.createEl("p", {
      text: "For example, the following request will return all notes in the root directory of your vault:",
    });
    apiKeyDiv.createEl("pre", {
      text: `GET /vault/ HTTP/1.1\n${
        this.plugin.settings.authorizationHeaderName ?? "Authorization"
      }: Bearer ${this.plugin.settings.apiKey}`,
    });

    const seeMore = apiKeyDiv.createEl("p");
    seeMore.innerHTML = `
      Comprehensive documentation of what API endpoints are available can
      be found in
      <a href="https://coddingtonbear.github.io/obsidian-local-rest-api/">the online docs</a>.
    `;

    containerEl.createEl("h3", { text: "Settings" });

    if (remainingCertificateValidityDays < 0) {
      const expiredCertDiv = apiKeyDiv.createEl("div");
      expiredCertDiv.classList.add("certificate-expired");
      expiredCertDiv.innerHTML = `
        <b>Your certificate has expired!</b>
        You must re-generate your certificate below by pressing
        the "Re-generate Certificates" button below in
        order to connect securely to this API.
      `;
    } else if (remainingCertificateValidityDays < 30) {
      const soonExpiringCertDiv = apiKeyDiv.createEl("div");
      soonExpiringCertDiv.classList.add("certificate-expiring-soon");
      soonExpiringCertDiv.innerHTML = `
        <b>Your certificate will expire in ${Math.floor(
          remainingCertificateValidityDays
        )} day${
        Math.floor(remainingCertificateValidityDays) === 1 ? "" : "s"
      }s!</b>
        You should re-generate your certificate below by pressing
        the "Re-generate Certificates" button below in
        order to continue to connect securely to this API.
      `;
    }
    if (shouldRegenerateCertificate) {
      const shouldRegenerateCertificateDiv = apiKeyDiv.createEl("div");
      shouldRegenerateCertificateDiv.classList.add(
        "certificate-regeneration-recommended"
      );
      shouldRegenerateCertificateDiv.innerHTML = `
        <b>You should re-generate your certificate!</b>
        Your certificate was generated using earlier standards than
        are currently used by Obsidian Local REST API NG. Some systems
        or tools may not accept your certificate with its current
        configuration, and re-generating your certificate may
        improve compatibility with such tools.  To re-generate your
        certificate, press the "Re-generate Certificates" button
        below.
      `;
    }

    new Setting(containerEl)
      .setName("Enable Non-encrypted (HTTP) Server")
      .setDesc(
        "Enables a non-encrypted (HTTP) server on the port designated below.  By default this plugin requires a secure HTTPS connection, but in safe environments you may turn on the non-encrypted server to simplify interacting with the API. Interactions with the API will still require the API Key shown above.  Under no circumstances is it recommended that you expose this service to the internet, especially if you turn on this feature!"
      )
      .addToggle((cb) =>
        cb
          .onChange((value) => {
            const originalValue = this.plugin.settings.enableInsecureServer;
            this.plugin.settings.enableInsecureServer = value;
            this.plugin.saveSettings();
            this.plugin.refreshServerState();
            // If our target value differs,
            if (value !== originalValue) {
              this.display();
            }
          })
          .setValue(this.plugin.settings.enableInsecureServer)
      );

    new Setting(containerEl)
      .setName("Reset All Cryptography")
      .setDesc(
        `Pressing this button will cause your certificate,
        private key, public key, and API key to be regenerated.
        This settings panel will be closed when you press this.`
      )
      .addButton((cb) => {
        cb.setWarning()
          .setButtonText("Reset All Crypto")
          .onClick(() => {
            delete this.plugin.settings.apiKey;
            delete this.plugin.settings.crypto;
            this.plugin.saveSettings();
            this.plugin.unload();
            this.plugin.load();
          });
      });

    new Setting(containerEl)
      .setName("Re-generate Certificates")
      .setDesc(
        `Pressing this button will cause your certificate,
        private key,  and public key to be re-generated, but your API key will remain unchanged. 
        This settings panel will be closed when you press this.`
      )
      .addButton((cb) => {
        cb.setWarning()
          .setButtonText("Re-generate Certificates")
          .onClick(() => {
            delete this.plugin.settings.crypto;
            this.plugin.saveSettings();
            this.plugin.unload();
            this.plugin.load();
          });
      });

    new Setting(containerEl)
      .setName("Restore Default Settings")
      .setDesc(
        `Pressing this button will reset this plugin's
        settings to defaults.
        This settings panel will be closed when you press this.`
      )
      .addButton((cb) => {
        cb.setWarning()
          .setButtonText("Restore Defaults")
          .onClick(() => {
            this.plugin.settings = Object.assign({}, DEFAULT_SETTINGS);
            this.plugin.saveSettings();
            this.plugin.unload();
            this.plugin.load();
          });
      });

    // ── Security Filtering Settings (NG Fork) ──
    containerEl.createEl("hr");
    containerEl.createEl("h3", { text: "Security Filtering" });
    containerEl.createEl("p", {
      text: "Control which vault files are accessible via the API. Default policy: deny all unless explicitly allowed.",
    });

    new Setting(containerEl)
      .setName("Enable Security Filtering")
      .setDesc(
        "When enabled, all vault access is filtered by the rules below. Disable to restore unrestricted access."
      )
      .addToggle((cb) =>
        cb
          .setValue(this.plugin.settings.securityFilterEnabled ?? SECURITY_FILTER_DEFAULTS.securityFilterEnabled)
          .onChange((value) => {
            this.plugin.settings.securityFilterEnabled = value;
            this.plugin.saveSettings();
            this.display();
          })
      );

    if (this.plugin.settings.securityFilterEnabled ?? SECURITY_FILTER_DEFAULTS.securityFilterEnabled) {
      new Setting(containerEl)
        .setName("Default Policy")
        .setDesc(
          "What happens when no filter rule matches a file. 'Deny' blocks all unmatched files (recommended). 'Allow' permits all unmatched files."
        )
        .addDropdown((cb) =>
          cb
            .addOption("deny", "Deny (recommended)")
            .addOption("allow", "Allow")
            .onChange((value) => {
              this.plugin.settings.defaultPolicy = value as FilterMode;
              this.plugin.saveSettings();
            })
            .setValue(this.plugin.settings.defaultPolicy ?? SECURITY_FILTER_DEFAULTS.defaultPolicy)
        );

      new Setting(containerEl)
        .setName("Read-Only Mode")
        .setDesc(
          "Block all write operations (PUT, POST, PATCH, DELETE) on vault files and commands."
        )
        .addToggle((cb) =>
          cb
            .setValue(this.plugin.settings.readOnlyMode ?? SECURITY_FILTER_DEFAULTS.readOnlyMode)
            .onChange((value) => {
              this.plugin.settings.readOnlyMode = value;
              this.plugin.saveSettings();
            })
        );

      // ── Global Tags ──
      new Setting(containerEl)
        .setName("Global Allow Tag")
        .setDesc("Files with this tag are always accessible, regardless of other rules.")
        .addText((cb) =>
          cb
            .onChange((value) => {
              this.plugin.settings.globalAllowTag = value;
              this.plugin.saveSettings();
            })
            .setValue(this.plugin.settings.globalAllowTag ?? SECURITY_FILTER_DEFAULTS.globalAllowTag)
        );

      new Setting(containerEl)
        .setName("Global Deny Tag")
        .setDesc("Files with this tag are always denied, overriding all other rules.")
        .addText((cb) =>
          cb
            .onChange((value) => {
              this.plugin.settings.globalDenyTag = value;
              this.plugin.saveSettings();
            })
            .setValue(this.plugin.settings.globalDenyTag ?? SECURITY_FILTER_DEFAULTS.globalDenyTag)
        );

      // ── Access Rules (from access-rules.conf) ──
      containerEl.createEl("h4", { text: "Access Rules" });
      containerEl.createEl("p", {
        text: `Rules are loaded from access-rules.conf in the plugin directory. First match wins. Supported types: folder, name, tag, keyword.`,
        cls: "setting-item-description",
      });

      new Setting(containerEl)
        .setName("Reload Rules")
        .setDesc("Reload rules from access-rules.conf after external edits.")
        .addButton((cb) =>
          cb.setButtonText("Reload").onClick(async () => {
            await this.reloadAndRefresh(containerEl);
          })
        );

      await this.renderAccessRules(containerEl);

      // ── Filter Diagnostics ──
      containerEl.createEl("hr");
      containerEl.createEl("h4", { text: "Filter Diagnostics" });
      const diagSetting = new Setting(containerEl)
        .setName("Test Filter")
        .setDesc("Enter a vault path to test whether it would be allowed or denied.");
      let diagInput = "";
      diagSetting
        .addText((cb) =>
          cb
            .setPlaceholder("path/to/note.md")
            .onChange((value) => {
              diagInput = value;
            })
        )
        .addButton((cb) =>
          cb.setButtonText("Test").onClick(async () => {
            if (!diagInput) return;
            const engine = this.plugin.filterEngine;
            if (!engine) return;
            const decision = await engine.evaluateFile(
              diagInput,
              this.plugin.settings as any,
              "GET",
            );
            const resultEl = containerEl.querySelector(".diag-result");
            if (resultEl) resultEl.remove();
            const el = containerEl.createEl("div", { cls: "diag-result" });
            el.style.padding = "8px";
            el.style.margin = "8px 0";
            el.style.borderRadius = "4px";
            el.style.backgroundColor = decision.allowed
              ? "var(--background-modifier-success)"
              : "var(--background-modifier-error)";
            el.setText(
              `${decision.allowed ? "ALLOWED" : "DENIED"}: ${decision.reason}`
            );
          })
        );

      // ── Logs ──
      containerEl.createEl("hr");
      containerEl.createEl("h4", { text: "Logs" });

      new Setting(containerEl)
        .setName("View Access Log")
        .setDesc("View recent HTTP access log entries (Combined Log Format).")
        .addButton((cb) =>
          cb.setButtonText("View").onClick(() => {
            if (this.plugin.auditLogger) {
              new LogViewerModal(this.app, this.plugin.auditLogger, "access").open();
            }
          })
        );

      new Setting(containerEl)
        .setName("View Error Log")
        .setDesc("View recent security events (denials, errors, warnings).")
        .addButton((cb) =>
          cb.setButtonText("View").onClick(() => {
            if (this.plugin.auditLogger) {
              new LogViewerModal(this.app, this.plugin.auditLogger, "error").open();
            }
          })
        );

      new Setting(containerEl)
        .setName("Clear Logs")
        .setDesc("Clear both access and error log files.")
        .addButton((cb) =>
          cb
            .setWarning()
            .setButtonText("Clear All Logs")
            .onClick(async () => {
              if (this.plugin.auditLogger) {
                await this.plugin.auditLogger.clearLogs();
              }
            })
        );
    }

    containerEl.createEl("hr");

    new Setting(containerEl)
      .setName("Show advanced settings")
      .setDesc(
        `Advanced settings are dangerous and may make your environment less secure.`
      )
      .addToggle((cb) => {
        cb.onChange((value) => {
          if (this.showAdvancedSettings !== value) {
            this.showAdvancedSettings = value;
            this.display();
          }
        }).setValue(this.showAdvancedSettings);
      });

    if (this.showAdvancedSettings) {
      containerEl.createEl("hr");
      containerEl.createEl("h3", {
        text: "Advanced Settings",
      });
      containerEl.createEl("p", {
        text: `
          The settings below are potentially dangerous and
          are intended for use only by people who know what
          they are doing. Do not change any of these settings if
          you do not understand what that setting is used for
          and what security impacts changing that setting will have.
        `,
      });
      const noWarrantee = containerEl.createEl("p");
      noWarrantee.createEl("span", {
        text: `
          Use of this software is licensed to you under the
          MIT license, and it is important that you understand that 
          this license provides you with no warranty.
          For the complete license text please see
        `,
      });
      noWarrantee.createEl("a", {
        href: LicenseUrl,
        text: LicenseUrl,
      });
      noWarrantee.createEl("span", { text: "." });

      new Setting(containerEl)
        .setName("Enable Encrypted (HTTPs) Server")
        .setDesc(
          `
          This controls whether the HTTPs server is enabled.  You almost certainly want to leave this switch in its default state ('on'),
          but may find it useful to turn this switch off for
          troubleshooting.
        `
        )
        .addToggle((cb) =>
          cb
            .onChange((value) => {
              const originalValue = this.plugin.settings.enableSecureServer;
              this.plugin.settings.enableSecureServer = value;
              this.plugin.saveSettings();
              this.plugin.refreshServerState();
              if (value !== originalValue) {
                this.display();
              }
            })
            .setValue(this.plugin.settings.enableSecureServer ?? true)
        );

      new Setting(containerEl)
        .setName("Encrypted (HTTPS) Server Port")
        .setDesc(
          "This configures the port on which your REST API will listen for HTTPS connections.  It is recommended that you leave this port with its default setting as tools integrating with this API may expect the default port to be in use.  Under no circumstances is it recommended that you expose this service directly to the internet."
        )
        .addText((cb) =>
          cb
            .onChange((value) => {
              this.plugin.settings.port = parseInt(value, 10);
              this.plugin.saveSettings();
              this.plugin.refreshServerState();
            })
            .setValue(this.plugin.settings.port.toString())
        );

      new Setting(containerEl)
        .setName("Non-encrypted (HTTP) Server Port")
        .addText((cb) =>
          cb
            .onChange((value) => {
              this.plugin.settings.insecurePort = parseInt(value, 10);
              this.plugin.saveSettings();
              this.plugin.refreshServerState();
            })
            .setValue(this.plugin.settings.insecurePort.toString())
        );

      new Setting(containerEl).setName("API Key").addText((cb) => {
        cb.onChange((value) => {
          this.plugin.settings.apiKey = value;
          this.plugin.saveSettings();
          this.plugin.refreshServerState();
        }).setValue(this.plugin.settings.apiKey);
      });
      new Setting(containerEl)
        .setName("Certificate Hostnames")
        .setDesc(
          `
          List of extra hostnames to add
          to your certificate's \`subjectAltName\` field.
          One hostname per line.
          You must click the "Re-generate Certificates" button above after changing this value
          for this to have an effect.  This is useful for
          situations in which you are accessing Obsidian
          from a hostname other than the host on which
          it is running.
      `
        )
        .addTextArea((cb) =>
          cb
            .onChange((value) => {
              this.plugin.settings.subjectAltNames = value;
              this.plugin.saveSettings();
            })
            .setValue(this.plugin.settings.subjectAltNames)
        );
      new Setting(containerEl).setName("Certificate").addTextArea((cb) =>
        cb
          .onChange((value) => {
            this.plugin.settings.crypto.cert = value;
            this.plugin.saveSettings();
            this.plugin.refreshServerState();
          })
          .setValue(this.plugin.settings.crypto.cert)
      );
      new Setting(containerEl).setName("Public Key").addTextArea((cb) =>
        cb
          .onChange((value) => {
            this.plugin.settings.crypto.publicKey = value;
            this.plugin.saveSettings();
            this.plugin.refreshServerState();
          })
          .setValue(this.plugin.settings.crypto.publicKey)
      );
      new Setting(containerEl).setName("Private Key").addTextArea((cb) =>
        cb
          .onChange((value) => {
            this.plugin.settings.crypto.privateKey = value;
            this.plugin.saveSettings();
            this.plugin.refreshServerState();
          })
          .setValue(this.plugin.settings.crypto.privateKey)
      );
      new Setting(containerEl).setName("Authorization Header").addText((cb) => {
        cb.onChange((value) => {
          if (value !== DefaultBearerTokenHeaderName) {
            this.plugin.settings.authorizationHeaderName = value;
          } else {
            delete this.plugin.settings.authorizationHeaderName;
          }
          this.plugin.saveSettings();
          this.plugin.refreshServerState();
        }).setValue(
          this.plugin.settings.authorizationHeaderName ??
            DefaultBearerTokenHeaderName
        );
      });
      new Setting(containerEl).setName("Binding Host").addText((cb) => {
        cb.onChange((value) => {
          if (value !== DefaultBindingHost) {
            this.plugin.settings.bindingHost = value;
          } else {
            delete this.plugin.settings.bindingHost;
          }
          this.plugin.saveSettings();
          this.plugin.refreshServerState();
        }).setValue(this.plugin.settings.bindingHost ?? DefaultBindingHost);
      });
    }
  }

  /**
   * Reload rules from conf file, update the filter engine, and re-render the settings tab.
   */
  private async reloadAndRefresh(containerEl: HTMLElement): Promise<void> {
    const engine = this.plugin.filterEngine;
    if (engine) {
      await engine.reloadRules(
        this.plugin.app.vault.adapter,
        this.plugin.pluginDir,
      );
    }
    this.display();
  }

  /**
   * Render all rules from access-rules.conf with toggle/delete controls.
   */
  private async renderAccessRules(containerEl: HTMLElement): Promise<void> {
    const adapter = this.plugin.app.vault.adapter;
    const pluginDir = this.plugin.pluginDir;

    const result = await loadRulesFile(adapter, pluginDir);
    const entries: RuleEntry[] = result?.entries ?? [];

    if (entries.length === 0) {
      containerEl.createEl("p", {
        text: "No rules defined yet. Add rules below or edit access-rules.conf directly.",
        cls: "setting-item-description",
      });
    }

    const TYPE_LABELS: Record<string, string> = {
      folder: "Folder",
      name: "Name",
      tag: "Tag",
      keyword: "Keyword",
    };

    for (const entry of entries) {
      const { rule, filterType, lineNumber } = entry;
      const typeLabel = TYPE_LABELS[filterType] ?? filterType;
      const methodStr = rule.methods?.length
        ? ` [${rule.methods.join(",")}]`
        : "";
      const regexStr = rule.isRegex ? " [regex]" : "";

      const ruleSetting = new Setting(containerEl)
        .setName(
          `${rule.enabled ? "" : "[disabled] "}${rule.mode.toUpperCase()} ${typeLabel}: ${rule.pattern}`,
        )
        .setDesc(`Line ${lineNumber + 1}${methodStr}${regexStr}`);

      ruleSetting.addToggle((cb) =>
        cb.setValue(rule.enabled).onChange(async (value) => {
          await toggleRuleByLine(adapter, pluginDir, lineNumber, value);
          await this.reloadAndRefresh(containerEl);
        }),
      );

      ruleSetting.addButton((cb) =>
        cb
          .setWarning()
          .setButtonText("Delete")
          .onClick(async () => {
            await removeRuleByLine(adapter, pluginDir, lineNumber);
            await this.reloadAndRefresh(containerEl);
          }),
      );
    }

    new Setting(containerEl).addButton((cb) =>
      cb.setButtonText("Add rule").onClick(() => {
        new AddRuleModal(this.app, async (filterType, rule) => {
          await appendRule(adapter, pluginDir, filterType, rule);
          await this.reloadAndRefresh(containerEl);
        }).open();
      }),
    );
  }
}

class AddRuleModal extends Modal {
  private onSubmit: (filterType: string, rule: FilterRule) => void;
  private mode: FilterMode = "allow";
  private filterType: string = "folder";
  private pattern = "";
  private isRegex = false;
  private methods: HttpMethod[] = [];
  private allMethods = true;

  constructor(
    app: App,
    onSubmit: (filterType: string, rule: FilterRule) => void,
  ) {
    super(app);
    this.onSubmit = onSubmit;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.createEl("h2", { text: "Add Access Rule" });

    new Setting(contentEl)
      .setName("Mode")
      .addDropdown((cb) =>
        cb
          .addOption("allow", "Allow")
          .addOption("deny", "Deny")
          .onChange((value) => {
            this.mode = value as FilterMode;
          })
          .setValue(this.mode),
      );

    new Setting(contentEl)
      .setName("Filter Type")
      .setDesc("What aspect of the file to match against.")
      .addDropdown((cb) =>
        cb
          .addOption("folder", "Folder (path glob)")
          .addOption("name", "Document Name")
          .addOption("tag", "Tag")
          .addOption("keyword", "Keyword (content)")
          .onChange((value) => {
            this.filterType = value;
          })
          .setValue(this.filterType),
      );

    new Setting(contentEl)
      .setName("Pattern")
      .setDesc("Glob pattern, tag name, or keyword to match.")
      .addText((cb) =>
        cb
          .setPlaceholder("Projects/**")
          .onChange((value) => {
            this.pattern = value;
          }),
      );

    new Setting(contentEl)
      .setName("Is Regex")
      .setDesc("Treat pattern as a regular expression instead of glob.")
      .addToggle((cb) =>
        cb.onChange((value) => {
          this.isRegex = value;
        }),
      );

    new Setting(contentEl)
      .setName("All Methods")
      .setDesc("Apply to all HTTP methods.")
      .addToggle((cb) =>
        cb
          .setValue(true)
          .onChange((value) => {
            this.allMethods = value;
            this.contentEl.empty();
            this.onOpen();
          }),
      );

    if (!this.allMethods) {
      const methodOptions: HttpMethod[] = [
        "GET",
        "PUT",
        "POST",
        "PATCH",
        "DELETE",
      ];
      for (const m of methodOptions) {
        new Setting(contentEl)
          .setName(m)
          .addToggle((cb) =>
            cb.onChange((value) => {
              if (value) {
                if (!this.methods.includes(m)) this.methods.push(m);
              } else {
                this.methods = this.methods.filter((x) => x !== m);
              }
            }),
          );
      }
    }

    new Setting(contentEl).addButton((cb) =>
      cb
        .setCta()
        .setButtonText("Add Rule")
        .onClick(() => {
          if (!this.pattern) return;
          this.onSubmit(this.filterType, {
            id: crypto.randomUUID(),
            mode: this.mode,
            pattern: this.pattern,
            isRegex: this.isRegex,
            enabled: true,
            description: "",
            methods: this.allMethods ? undefined : this.methods,
          });
          this.close();
        }),
    );
  }

  onClose(): void {
    this.contentEl.empty();
  }
}

class LogViewerModal extends Modal {
  private auditLogger: AuditLogger;
  private logType: "access" | "error";

  constructor(app: App, auditLogger: AuditLogger, logType: "access" | "error") {
    super(app);
    this.auditLogger = auditLogger;
    this.logType = logType;
  }

  async onOpen(): Promise<void> {
    const { contentEl } = this;
    const title = this.logType === "access" ? "Access Log" : "Error Log";
    contentEl.createEl("h2", { text: `${title} (Recent 100)` });

    const lines = await this.auditLogger.readRecentLines(this.logType, 100);

    if (lines.length === 0) {
      contentEl.createEl("p", { text: "No log entries found." });
      return;
    }

    const pre = contentEl.createEl("pre");
    pre.style.maxHeight = "500px";
    pre.style.overflow = "auto";
    pre.style.fontSize = "12px";
    pre.style.fontFamily = "var(--font-monospace)";
    pre.style.whiteSpace = "pre-wrap";
    pre.style.wordBreak = "break-all";
    pre.style.padding = "8px";
    pre.style.backgroundColor = "var(--background-secondary)";
    pre.style.borderRadius = "4px";

    for (const line of lines) {
      const span = pre.createEl("span");
      span.setText(line + "\n");
      if (this.logType === "error") {
        if (line.includes("[error]")) {
          span.style.color = "var(--text-error)";
        } else if (line.includes("[warn]")) {
          span.style.color = "var(--text-accent)";
        }
      }
    }
  }

  onClose(): void {
    this.contentEl.empty();
  }
}

export const getAPI = (
  app: App,
  manifest: PluginManifest
): LocalRestApiPublicApi | undefined => {
  const plugin = app.plugins.plugins["local-rest-api-ng"];
  if (plugin) {
    return (plugin as unknown as LocalRestApi).getPublicApi(manifest);
  }
};
