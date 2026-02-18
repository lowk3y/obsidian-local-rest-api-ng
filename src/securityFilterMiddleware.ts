import type { App } from "obsidian";
import type express from "express";
import type { FilterEngine } from "./filters/filter-engine";
import type { AuditLogger } from "./audit/audit-logger";
import { SecurityErrorCode } from "./constants";

/** HTTP methods considered "write" operations */
const WRITE_METHODS = new Set(["PUT", "POST", "PATCH", "DELETE"]);

/** Routes that bypass security filtering entirely */
const EXEMPT_ROUTES = ["/", "/openapi.yaml"];

/** Routes that are write-capable and should respect read-only mode */
const WRITE_CAPABLE_PREFIXES = [
  "/vault/",
  "/active/",
  "/periodic/",
  "/commands/",
  "/open/",
];

/**
 * Normalize a vault path: collapse consecutive slashes, strip leading/trailing slashes.
 * "/PAI//foo/" → "PAI/foo/"
 * "///" → ""
 */
function normalizeVaultPath(raw: string): string {
  return raw.replace(/\/{2,}/g, "/").replace(/^\/+/, "");
}

export function createSecurityFilterMiddleware(
  app: App,
  getSettings: () => any,
  filterEngine: FilterEngine,
  auditLogger: AuditLogger,
): express.RequestHandler {
  return async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) => {
    try {
      const settings = getSettings();

      // Master toggle — if security filtering disabled, pass through completely
      if (!settings.securityFilterEnabled) {
        return next();
      }

      const method = (req.method ?? "GET").toUpperCase();
      const decodedPath = decodeURIComponent(req.path);

      // Exempt routes (status, cert download, OpenAPI spec)
      if (
        EXEMPT_ROUTES.includes(decodedPath) ||
        decodedPath.endsWith(".crt")
      ) {
        return next();
      }

      // ── Read-Only Mode Check ──
      if (settings.readOnlyMode && WRITE_METHODS.has(method)) {
        const isWriteRoute = WRITE_CAPABLE_PREFIXES.some((p) =>
          decodedPath.startsWith(p),
        );
        if (isWriteRoute) {
          auditLogger.logError({
            level: "warn",
            message: "write operation denied by read-only mode",
            clientIp: req.ip ?? "127.0.0.1",
            method,
            path: decodedPath,
            statusCode: 403,
          });
          res.status(403).json({
            message: "Access denied",
            errorCode: SecurityErrorCode.WriteOperationDenied,
          });
          return;
        }
      }

      // ── Vault Path Filtering ──
      if (decodedPath.startsWith("/vault/")) {
        const rawVaultPath = decodedPath.slice("/vault/".length);
        // Normalize: collapse double slashes, strip leading slashes
        const vaultPath = normalizeVaultPath(rawVaultPath);

        // Path traversal guard (defense in depth — upstream also checks)
        if (vaultPath.includes("..") || vaultPath.includes("\0")) {
          auditLogger.logError({
            level: "error",
            message: "path traversal attempt blocked",
            clientIp: req.ip ?? "127.0.0.1",
            method,
            path: decodedPath,
            statusCode: 400,
          });
          res.status(400).json({ message: "Bad request", errorCode: 40000 });
          return;
        }

        // File route (not directory listing)
        if (vaultPath && !vaultPath.endsWith("/")) {
          const decision = await filterEngine.evaluateFile(
            vaultPath,
            settings,
            method,
          );
          if (!decision.allowed) {
            auditLogger.logError({
              level: "warn",
              message: `access denied by ${decision.filterType ?? "default policy"}: ${decision.reason}`,
              clientIp: req.ip ?? "127.0.0.1",
              method,
              path: decodedPath,
              statusCode: 403,
            });
            res.status(403).json({
              message: "Access denied",
              errorCode: SecurityErrorCode.AccessDenied,
            });
            return;
          }
        }

        // Directory listing — attach response interceptor with directory prefix
        if (!vaultPath || vaultPath.endsWith("/")) {
          attachResponseInterceptor(
            res,
            filterEngine,
            settings,
            vaultPath, // pass the directory prefix for full-path reconstruction
          );
        }
      }

      // ── Active File Filtering ──
      if (decodedPath.startsWith("/active/")) {
        const activeFile = app.workspace.getActiveFile();
        if (activeFile) {
          const decision = await filterEngine.evaluateFile(
            activeFile.path,
            settings,
            method,
          );
          if (!decision.allowed) {
            auditLogger.logError({
              level: "warn",
              message: `active file access denied: ${decision.reason}`,
              clientIp: req.ip ?? "127.0.0.1",
              method,
              path: decodedPath,
              statusCode: 403,
            });
            res.status(403).json({
              message: "Access denied",
              errorCode: SecurityErrorCode.AccessDenied,
            });
            return;
          }
        }
      }

      // ── Search Result Filtering ──
      if (decodedPath.startsWith("/search")) {
        attachSearchInterceptor(res, filterEngine, settings);
      }

      // ── Command Filtering (read-only mode blocks all commands) ──
      if (
        decodedPath.startsWith("/commands/") &&
        method === "POST" &&
        settings.readOnlyMode
      ) {
        auditLogger.logError({
          level: "warn",
          message: "command execution denied by read-only mode",
          clientIp: req.ip ?? "127.0.0.1",
          method,
          path: decodedPath,
          statusCode: 403,
        });
        res.status(403).json({
          message: "Access denied",
          errorCode: SecurityErrorCode.WriteOperationDenied,
        });
        return;
      }

      next();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error("[REST API] Security filter error:", err);
      auditLogger.logError({
        level: "error",
        message: `security filter exception: ${message}`,
        clientIp: req.ip ?? "127.0.0.1",
        method: req.method,
        path: req.path,
        statusCode: 500,
      });
      next(err);
    }
  };
}

/**
 * Intercept res.json() to post-filter directory listings.
 * Strips denied file paths from { files: [...] } responses.
 * Prepends dirPrefix to each relative path before filtering.
 */
function attachResponseInterceptor(
  res: express.Response,
  filterEngine: FilterEngine,
  settings: any,
  dirPrefix: string,
): void {
  const originalJson = res.json.bind(res);
  res.json = function (body: any) {
    if (body?.files && Array.isArray(body.files)) {
      // Reconstruct full vault-relative paths for filtering
      const fullPaths = body.files.map((f: string) => `${dirPrefix}${f}`);
      filterEngine
        .filterPaths(fullPaths, settings)
        .then((filtered) => {
          // Strip the prefix back to return relative paths
          body.files = filtered.map((f: string) => f.slice(dirPrefix.length));
          originalJson.call(res, body);
        })
        .catch((err) => {
          console.error("[REST API] Directory filter error:", err);
          body.files = [];
          originalJson.call(res, body);
        });
      return res;
    }
    return originalJson.call(res, body);
  } as any;
}

/**
 * Intercept res.json() to post-filter search results.
 * Strips denied files from search result arrays.
 */
function attachSearchInterceptor(
  res: express.Response,
  filterEngine: FilterEngine,
  settings: any,
): void {
  const originalJson = res.json.bind(res);
  res.json = function (body: any) {
    if (Array.isArray(body)) {
      filterEngine
        .filterSearchResults(body, settings)
        .then((filtered) => {
          originalJson.call(res, filtered);
        })
        .catch((err) => {
          console.error("[REST API] Search filter error:", err);
          originalJson.call(res, []);
        });
      return res;
    }
    return originalJson.call(res, body);
  } as any;
}
