import Alpine from "alpinejs";
import htmx from "htmx.org";

Alpine.data("serversList", () => ({
    loading: true,
    hasServers: true,
    servers: [],

    hasError: false,
    errorMessage: "",

    init() {
      // Error handling
      this.$el.addEventListener("htmx:afterRequest", (event) => {
        const { detail } = event as CustomEvent<{
          successful: boolean;
          xhr: XMLHttpRequest;
        }>;
        const xhr = detail.xhr;

        if (!detail.successful) {
          this.hasError = true;
          try {
            const errorResponse = JSON.parse(xhr.responseText).error;
            this.errorMessage = errorResponse;
          } catch {
            this.errorMessage = "An error has occurred";
          }
        }
      });
      // Get list of servers
      const loader = this.$refs.serversLoader as HTMLElement | undefined;

      loader?.addEventListener(
        "htmx:afterRequest",
        (event) => {
          const { detail } = event as CustomEvent<{
            successful: boolean;
            xhr: XMLHttpRequest;
          }>;
          const xhr = detail.xhr;
          const response = xhr.response;

          if (detail.successful) {
            if (response === "[]") {
              this.hasServers = false;
            } else {
              this.hasServers = true;
              this.servers = JSON.parse(response);
              localStorage.setItem("serversList", xhr.response);
            }
            // Process the new content with htmx
            this.$nextTick(() => {
              const list = this.$el.querySelector("#ul-servers-list");
              if (list) {
                htmx.process(list);
              }
            });
          }
        },
      );
    },

    statusIndicatorClass(status: unknown) {
      const value = typeof status === "string" ? status.toLowerCase() : "";

      if (value === "running") {
        return "bg-green-500";
      }

      if (value === "error") {
        return "bg-red-500";
      }

      if (value === "paused" || value === "pausing" || value === "stopped") {
        return "bg-red-500";
      }

      return "bg-yellow-500";
    },

    statusIndicatorLabel(status: unknown) {
      const value = typeof status === "string" ? status.toLowerCase() : "";

      if (value === "running") {
        return "Running";
      }

      if (value === "error") {
        return "Error";
      }

      if (value === "paused" || value === "pausing" || value === "stopped") {
        return value === "stopped" ? "Stopped" : "Paused";
      }

      return "Unknown";
    },
  }));
