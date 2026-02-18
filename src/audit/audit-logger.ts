import type { DataAdapter } from "obsidian";

/**
 * Format a Date as a CLF (Common Log Format) timestamp:
 * [10/Oct/2000:13:55:36 -0700]
 */
function formatCLFDate(date: Date): string {
  const months = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  ];
  const day = date.getDate().toString().padStart(2, "0");
  const month = months[date.getMonth()];
  const year = date.getFullYear();
  const hours = date.getHours().toString().padStart(2, "0");
  const minutes = date.getMinutes().toString().padStart(2, "0");
  const seconds = date.getSeconds().toString().padStart(2, "0");
  const tzOffset = -date.getTimezoneOffset();
  const tzSign = tzOffset >= 0 ? "+" : "-";
  const tzHours = Math.floor(Math.abs(tzOffset) / 60)
    .toString()
    .padStart(2, "0");
  const tzMins = (Math.abs(tzOffset) % 60).toString().padStart(2, "0");
  return `[${day}/${month}/${year}:${hours}:${minutes}:${seconds} ${tzSign}${tzHours}${tzMins}]`;
}

export class AuditLogger {
  private accessLogPath: string | null = null;
  private errorLogPath: string | null = null;
  private adapter: DataAdapter | null = null;

  constructor(adapter: DataAdapter, pluginDir: string) {
    this.adapter = adapter;
    this.accessLogPath = `${pluginDir}/logs/access.log`;
    this.errorLogPath = `${pluginDir}/logs/error.log`;
    this.ensureLogsDir(pluginDir);
  }

  /**
   * Ensure the logs/ directory exists under the plugin directory.
   */
  private ensureLogsDir(pluginDir: string): void {
    const logsDir = `${pluginDir}/logs`;
    this.adapter!.exists(logsDir).then((exists) => {
      if (!exists) {
        this.adapter!.mkdir(logsDir).catch((err) => {
          console.error("[REST API] Failed to create logs directory:", err);
        });
      }
    }).catch((err) => {
      console.error("[REST API] Failed to check logs directory:", err);
    });
  }

  /**
   * Append a line to a log file using Obsidian's vault adapter.
   * Fire-and-forget — never blocks the request.
   */
  private appendToLog(logPath: string, line: string): void {
    if (!this.adapter) return;

    this.adapter.exists(logPath).then((exists) => {
      if (exists) {
        this.adapter!.append(logPath, line);
      } else {
        this.adapter!.write(logPath, line);
      }
    }).catch((err) => {
      console.error(`[REST API] Failed to write log ${logPath}:`, err);
    });
  }

  /**
   * Write an access log line in Combined Log Format (nginx/apache style).
   * Logs ALL requests — not just security-filtered ones.
   *
   * Format:
   * remote_addr - - [time] "method path HTTP/ver" status bytes "referer" "user-agent"
   */
  logAccess(entry: {
    remoteAddr: string;
    method: string;
    path: string;
    httpVersion: string;
    statusCode: number;
    contentLength: number;
    referer: string;
    userAgent: string;
  }): void {
    if (!this.accessLogPath) return;

    const now = new Date();
    const clf = formatCLFDate(now);
    const referer = entry.referer || "-";
    const ua = entry.userAgent || "-";
    const contentLength = entry.contentLength > 0 ? entry.contentLength.toString() : "-";

    const line = `${entry.remoteAddr} - - ${clf} "${entry.method} ${entry.path} HTTP/${entry.httpVersion}" ${entry.statusCode} ${contentLength} "${referer}" "${ua}"\n`;

    this.appendToLog(this.accessLogPath, line);
  }

  /**
   * Write an error log line in nginx error log format.
   * Logs denied requests, filter errors, middleware errors, and server errors.
   *
   * Format:
   * YYYY/MM/DD HH:MM:SS [level] message, client: IP, method: METHOD, path: PATH
   */
  logError(entry: {
    level: "error" | "warn" | "info";
    message: string;
    clientIp?: string;
    method?: string;
    path?: string;
    statusCode?: number;
  }): void {
    if (!this.errorLogPath) return;

    const now = new Date();
    const date = [
      now.getFullYear(),
      (now.getMonth() + 1).toString().padStart(2, "0"),
      now.getDate().toString().padStart(2, "0"),
    ].join("/");
    const time = [
      now.getHours().toString().padStart(2, "0"),
      now.getMinutes().toString().padStart(2, "0"),
      now.getSeconds().toString().padStart(2, "0"),
    ].join(":");

    const parts = [`${date} ${time} [${entry.level}] ${entry.message}`];
    if (entry.clientIp) parts.push(`client: ${entry.clientIp}`);
    if (entry.method) parts.push(`method: ${entry.method}`);
    if (entry.path) parts.push(`path: ${entry.path}`);
    if (entry.statusCode) parts.push(`status: ${entry.statusCode}`);

    const line = parts.join(", ") + "\n";

    this.appendToLog(this.errorLogPath, line);
  }

  /**
   * Read the most recent lines from a log file.
   */
  async readRecentLines(logType: "access" | "error", count = 100): Promise<string[]> {
    const path = logType === "access" ? this.accessLogPath : this.errorLogPath;
    if (!path || !this.adapter) return [];
    const exists = await this.adapter.exists(path);
    if (!exists) return [];
    const content = await this.adapter.read(path);
    const lines = content.split("\n").filter(l => l.trim());
    return lines.slice(-count);
  }

  /**
   * Clear both log files.
   */
  async clearLogs(): Promise<void> {
    if (this.accessLogPath && this.adapter) {
      const exists = await this.adapter.exists(this.accessLogPath);
      if (exists) await this.adapter.write(this.accessLogPath, "");
    }
    if (this.errorLogPath && this.adapter) {
      const exists = await this.adapter.exists(this.errorLogPath);
      if (exists) await this.adapter.write(this.errorLogPath, "");
    }
  }

  /**
   * Get the path to the access log file.
   */
  getAccessLogPath(): string | null {
    return this.accessLogPath;
  }

  /**
   * Get the path to the error log file.
   */
  getErrorLogPath(): string | null {
    return this.errorLogPath;
  }

  /**
   * Clean up resources.
   */
  async destroy(): Promise<void> {
    // No periodic timers to clean up anymore
  }
}
