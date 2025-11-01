import Alpine from "alpinejs";
import htmx from "htmx.org";

type ConsoleEntry = {
  key: number;
  time: string;
  level: string;
  text: string;
  className: string;
  raw: string;
};

type ParsedLogLine = {
  time: string;
  level: string;
  text: string;
  raw: string;
};

type EnvironmentEntry = {
  key: string;
  value: string;
};

Alpine.data("serverInfo", () => ({
    serverName: new URLSearchParams(window.location.search).get("name") ?? "",
    id: "",
    createdAt: "",
    updatedAt: "",
    status: "",
    serverUrl: "",
    environment: [] as EnvironmentEntry[],
    actionFeedbackMessage: "",
    actionFeedbackType: "",
    command: "",
    commandResult: "",
    commandResultType: "",
    notFound: false,
    notFoundMessage: "",
    logMessages: [] as ConsoleEntry[],
    logSocket: null as WebSocket | null,
    logStatus: "",
    logAutoscroll: true,
    logReconnectTimer: null as number | null,
    logReconnectAttempts: 0,
    logSequence: 0,
    activeLogServerId: null as number | null,
    maxLogEntries: 400,
    consoleScrollCleanup: null as (() => void) | null,
    beforeUnloadHandler: null as (() => void) | null,
    showLogLegend: false,

    get hasEnvironment() {
      return Array.isArray(this.environment) && this.environment.length > 0;
    },

    get hasConsoleLogs() {
      return Array.isArray(this.logMessages) && this.logMessages.length > 0;
    },

    asString(value: unknown) {
      if (value === null || value === undefined) {
        return "";
      }

      return String(value);
    },

    refreshServerInfo() {
      const infoRef = this.$refs.getServerInfo as HTMLElement | undefined;

      if (infoRef) {
        htmx.trigger(infoRef, "refreshServerInfo", null);
      }
    },

    setActionFeedback(message: string, type: "success" | "error") {
      this.actionFeedbackMessage = message;
      this.actionFeedbackType = type;
    },

    setCommandResult(message: string, type: "success" | "error") {
      this.commandResult = message;
      this.commandResultType = type;
    },

    extractResponseMessage(xhr: XMLHttpRequest | undefined) {
      if (!xhr) {
        return "";
      }

      const text = xhr.responseText;

      if (!text) {
        return "";
      }

      try {
        const parsed = JSON.parse(text);

        if (typeof parsed === "string") {
          return parsed;
        }

        if (parsed?.message) {
          return parsed.message;
        }

        if (parsed?.error) {
          return parsed.error;
        }

        if (parsed?.output) {
          if (Array.isArray(parsed.output)) {
            return parsed.output.join("\n");
          }

          return String(parsed.output);
        }

        return text;
      } catch {
        return text;
      }
    },

    mapActionSuccess(action: string) {
      const messages: Record<string, string> = {
        start: "Server start requested.",
        restart: "Server restart requested.",
        stop: "Server stop requested.",
        delete: "Server deleted.",
      };

      return messages[action] ?? "Action completed.";
    },

    init() {
      const infoRef = this.$refs.getServerInfo as HTMLElement | undefined;

      infoRef?.addEventListener("htmx:afterRequest", (event) => {
        const { detail } = event as CustomEvent<{
          successful: boolean;
          xhr: XMLHttpRequest;
        }>;
        const xhr = detail.xhr as XMLHttpRequest | undefined;

        if (!detail.successful) {
          this.handleServerInfoError(xhr);
          return;
        }

        this.notFound = false;
        this.notFoundMessage = "";

        const parsed = this.safeParseJson(xhr?.responseText);

        if (!parsed || typeof parsed !== "object") {
          this.setActionFeedback(
            "Could not load server details.",
            "error",
          );
          return;
        }

        const response = parsed as Record<string, unknown>;

        this.id = this.asString(response["id"]);
        this.createdAt = this.asString(response["created_at"]);
        this.updatedAt = this.asString(response["updated_at"]);
        this.status = this.asString(response["status"]);
        const addressCandidate =
          response["url"] ??
          response["server_url"] ??
          response["ip"] ??
          response["server_ip"] ??
          "";
        this.serverUrl = this.asString(addressCandidate);
        this.environment = this.normalizeEnvironment(response["environment"]);
        this.ensureLogStream();

        this.$nextTick(() => {
          if (this.$refs.actionButtons) {
            htmx.process(this.$refs.actionButtons);
          }
        });
      });

      this.$el.addEventListener("htmx:afterRequest", (event) => {
        const actionType = (event.target as HTMLElement | null)?.dataset?.serverAction;

        if (!actionType) {
          return;
        }

        const { detail } = event as CustomEvent<{
          successful: boolean;
          xhr: XMLHttpRequest;
        }>;
        const xhr = detail.xhr as XMLHttpRequest | undefined;

        if (actionType === "exec") {
          if (detail.successful) {
            this.command = "";
            this.commandResult = "";
            this.commandResultType = "";
          } else {
            const message =
              this.extractResponseMessage(xhr) || "Could not execute the command.";
            this.setCommandResult(
              message,
              "error",
            );
          }

          return;
        }

        if (detail.successful) {
          this.actionFeedbackMessage = "";
          this.actionFeedbackType = "";

          if (actionType === "delete") {
            setTimeout(() => {
              window.location.href = "/dashboard.html";
            }, 600);

            return;
          }

          this.refreshServerInfo();
        } else {
          const message = this.extractResponseMessage(xhr);
          this.setActionFeedback(
            message || `Failed to ${actionType} server.`,
            "error",
          );
        }
      });

      this.$nextTick(() => {
        const getInfoRef = this.$refs.getServerInfo as HTMLElement | undefined;
        const commandForm = this.$refs.commandForm as HTMLElement | undefined;
        const actionButtons = this.$refs.actionButtons as HTMLElement | undefined;

        if (getInfoRef) {
          htmx.process(getInfoRef);
        }

        if (commandForm) {
          htmx.process(commandForm);
        }

        if (actionButtons) {
          htmx.process(actionButtons);
        }

        this.setupConsoleViewport();
        this.ensureBeforeUnloadHandler();
      });
    },

    handleServerInfoError(xhr: XMLHttpRequest | undefined) {
      const status = xhr?.status ?? 0;

      if (status === 404) {
        this.notFound = true;
        this.notFoundMessage =
          this.extractResponseMessage(xhr) ||
          "We couldn't find that server.";
        this.status = "";
        this.serverUrl = "";
        this.environment = [];
        this.id = "";
        this.createdAt = "";
        this.updatedAt = "";
        this.actionFeedbackMessage = "";
        this.actionFeedbackType = "";
        this.commandResult = "";
        this.commandResultType = "";
        this.stopLogStream();
        return;
      }

      this.setActionFeedback(
        this.extractResponseMessage(xhr) ||
          "Could not load server details.",
        "error",
      );

      this.serverUrl = "";
      this.stopLogStream();
    },

    safeParseJson(text: string | undefined | null): unknown {
      if (!text) {
        return null;
      }

      try {
        return JSON.parse(text);
      } catch {
        return null;
      }
    },

    normalizeEnvironment(raw: unknown): EnvironmentEntry[] {
      if (Array.isArray(raw)) {
        return raw
          .map((entry) => {
            if (entry && typeof entry === "object") {
              const record = entry as Record<string, unknown>;
              const keyCandidate =
                "key" in record
                  ? record["key"]
                  : "name" in record
                    ? record["name"]
                    : "";
              const valueCandidate =
                "value" in record ? record["value"] : record["val"];

              return {
                key: this.asString(keyCandidate),
                value: this.asString(valueCandidate),
              };
            }

            return {
              key: "",
              value: this.asString(entry),
            };
          })
          .filter((entry) => entry.key || entry.value);
      }

      if (raw && typeof raw === "object") {
        const entries = Object.entries(raw as Record<string, unknown>);

        return entries.map(([key, value]) => ({
          key: this.asString(key),
          value: this.asString(value),
        }));
      }

      return [];
    },

    ensureLogStream() {
      const numericId = Number(this.id);

      if (!Number.isFinite(numericId) || numericId <= 0) {
        this.stopLogStream();
        return;
      }

      const previousId = this.activeLogServerId;

      if (previousId !== null && previousId !== numericId) {
        this.clearConsole();
      }

      this.activeLogServerId = numericId;

      const normalizedStatus = (this.status || "").toLowerCase();
      const canStream = normalizedStatus === "running";

      if (!canStream) {
        this.stopLogStream();

        if (this.logStatus && this.logStatus !== "Idle") {
          this.logStatus = "Idle";
        }

        return;
      }

      if (this.activeLogServerId === numericId && this.logSocket) {
        const ready = this.logSocket.readyState;

        if (ready === WebSocket.OPEN || ready === WebSocket.CONNECTING) {
          return;
        }
      }

      this.startLogStream();
    },

    startLogStream() {
      this.stopLogStream();

      const serverId = this.activeLogServerId;

      if (serverId === null) {
        return;
      }

      this.logStatus = "Connecting…";

      try {
        const socket = new WebSocket(this.buildWebSocketUrl());
        this.logSocket = socket;

        socket.addEventListener("open", () => {
          this.resetLogReconnect();
          this.logStatus = "Connected";

          try {
            socket.send(
              JSON.stringify({
                server_id: serverId,
              }),
            );
          } catch (error) {
            console.warn("Could not subscribe to log stream", error);
          }
        });

        socket.addEventListener("message", (event) => {
          this.handleLogMessage(event.data);
        });

        socket.addEventListener("close", (event) => {
          if (this.logSocket === socket) {
            this.logSocket = null;
          }

          if (event.wasClean) {
            this.logStatus = "Disconnected";
          } else {
            this.logStatus = "Connection lost";
            this.scheduleLogReconnect();
          }
        });

        socket.addEventListener("error", () => {
          this.logStatus = "Connection error";
        });
      } catch (error) {
        console.error("Could not open log WebSocket", error);
        this.logStatus = "Failed to connect";
        this.scheduleLogReconnect();
      }
    },

    stopLogStream() {
      if (this.logReconnectTimer !== null) {
        window.clearTimeout(this.logReconnectTimer);
        this.logReconnectTimer = null;
      }

      if (this.logSocket) {
        try {
          this.logSocket.close(1000, "Console teardown");
        } catch (error) {
          console.warn("Error while closing log WebSocket", error);
        }

        this.logSocket = null;
      }
    },

    scheduleLogReconnect() {
      if (this.logReconnectTimer !== null) {
        return;
      }

      const attempt = this.logReconnectAttempts + 1;
      const delay = Math.min(5000, Math.pow(2, attempt) * 500);

      this.logReconnectAttempts = attempt;
      this.logReconnectTimer = window.setTimeout(() => {
        this.logReconnectTimer = null;
        this.startLogStream();
      }, delay);
    },

    resetLogReconnect() {
      this.logReconnectAttempts = 0;

      if (this.logReconnectTimer !== null) {
        window.clearTimeout(this.logReconnectTimer);
        this.logReconnectTimer = null;
      }
    },

    handleLogMessage(raw: unknown) {
      if (typeof raw !== "string") {
        this.appendConsoleLine(this.asString(raw));
        return;
      }

      try {
        const payload = JSON.parse(raw);

        if (payload && typeof payload === "object") {
          const record = payload as Record<string, unknown>;
          const type = record["type"];

          if (type === "status") {
            this.logStatus = this.asString(record["message"]) || "Streaming";
            return;
          }

          if (type === "log") {
            this.appendConsoleLine(this.asString(record["data"]));
            return;
          }
        }

        this.appendConsoleLine(raw);
      } catch {
        this.appendConsoleLine(raw);
      }
    },

    appendConsoleLine(text: string) {
      if (!text) {
        return;
      }

      const normalized = text.replace(/\r\n/g, "\n");
      const lines = normalized.split("\n");

      lines.forEach((line) => {
        if (!line || !line.trim()) {
          return;
        }

        const parsed = this.parseLogLine(line);
        const entry: ConsoleEntry = {
          key: ++this.logSequence,
          time: parsed.time,
          level: parsed.level,
          text: parsed.text,
          className: this.mapLogLevelClass(parsed.level),
          raw: parsed.raw,
        };

        this.logMessages.push(entry);
      });

      if (this.logMessages.length > this.maxLogEntries) {
        this.logMessages.splice(0, this.logMessages.length - this.maxLogEntries);
      }

      this.$nextTick(() => {
        this.scrollConsoleToBottom();
      });
    },

    clearConsole() {
      this.logMessages = [];
      this.logSequence = 0;
      this.logStatus = "";
      this.logAutoscroll = true;
      this.showLogLegend = false;
    },

    buildWebSocketUrl() {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const host = window.location.host;
      return `${protocol}//${host}/ws`;
    },

    parseLogLine(line: string): ParsedLogLine {
      const trimmed = line.trimEnd();

      const result: ParsedLogLine = {
        time: "",
        level: "",
        text: trimmed,
        raw: line,
      };

      if (!trimmed) {
        return result;
      }

      const pattern =
        /^\[(?<timestamp>[^\]]+)]\s+\[(?<thread>[^/]+)\/(?<level>[^\]]+)]\s*(?:\[(?<source>[^\]]+)])?\s*(?::\s*)?(?<message>.*)$/;
      const match = trimmed.match(pattern);

      if (!match || !match.groups) {
        return result;
      }

      const { timestamp, level, source, message } = match.groups;

      if (timestamp) {
        const parts = timestamp.split(" ");

        if (parts.length > 1) {
          const timePart = parts[1];
          result.time = timePart.split(".")[0] ?? timePart;
        }
      }

      if (level) {
        result.level = level.trim().toUpperCase();
      }

      let payload = message?.trim() ?? "";
      const normalizedSource = source?.trim();

      if (normalizedSource) {
        const cleanedSource = normalizedSource.replace(/\/$/, "");
        if (cleanedSource) {
          payload = payload ? `${cleanedSource}: ${payload}` : cleanedSource;
        }
      }

      result.text = payload || trimmed;

      return result;
    },

    mapLogLevelClass(level: string) {
      const normalized = level.toUpperCase();

      if (normalized.includes("ERROR") || normalized === "SEVERE") {
        return "text-red-300";
      }

      if (normalized.includes("WARN")) {
        return "text-amber-300";
      }

      if (normalized.includes("DEBUG")) {
        return "text-sky-300";
      }

      if (normalized.includes("INFO")) {
        return "text-emerald-200";
      }

      return "text-zinc-300";
    },

    scrollConsoleToBottom() {
      if (!this.logAutoscroll) {
        return;
      }

      const viewport = this.$refs.consoleViewport as HTMLElement | undefined;

      if (!viewport) {
        return;
      }

      viewport.scrollTop = viewport.scrollHeight;
    },

    setupConsoleViewport() {
      const viewport = this.$refs.consoleViewport as HTMLElement | undefined;

      if (!viewport || this.consoleScrollCleanup) {
        return;
      }

      const onScroll = (event: Event) => {
        if (!event.isTrusted) {
          return;
        }

        const distanceFromBottom =
          viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight;

        this.logAutoscroll = distanceFromBottom < 32;
      };

      viewport.addEventListener("scroll", onScroll);
      this.consoleScrollCleanup = () => {
        viewport.removeEventListener("scroll", onScroll);
      };
    },

    ensureBeforeUnloadHandler() {
      if (this.beforeUnloadHandler) {
        return;
      }

      const handler = () => {
        this.stopLogStream();

        if (this.consoleScrollCleanup) {
          this.consoleScrollCleanup();
          this.consoleScrollCleanup = null;
        }
      };

      window.addEventListener("beforeunload", handler);

      this.beforeUnloadHandler = handler;
    },
  }));
