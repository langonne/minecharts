import Alpine from "alpinejs";
import { fetchAuthInfo, isAdminUser, syncAdminFlag } from "./main";

type PasswordPayload = {
  current: string;
  new: string;
  confirm: string;
};

type AccountProfile = {
  id: string;
  email: string;
  username: string;
  permissions: number;
  is_admin: boolean;
  last_login: string;
};

type PasswordFormState = {
  email: string;
  passwordCurrent: string;
  passwordNew: string;
  passwordConfirm: string;
};

declare global {
  interface Window {
    accountPage?: ReturnType<typeof createAccountPageState>;
  }
}

function createAccountPageState() {
  return {
    loading: true,
    loadError: "",
    successMessage: "",
    errorMessage: "",
    userId: "",
    username: "",
    originalEmail: "",
    originalPermissions: 0,
    isAdmin: false,
    lastLogin: "—",
    form: {
      email: "",
      passwordCurrent: "",
      passwordNew: "",
      passwordConfirm: "",
    } as PasswordFormState,

    init() {
      this.fetchProfile();
    },

    async fetchProfile() {
      this.loading = true;
      this.loadError = "";
      try {
        const data = await fetchAuthInfo();

        if (!data) {
          throw new Error("Authentication information unavailable.");
        }

        const profile = this.normalizeProfile(data as Record<string, unknown>);

        this.userId = profile.id;
        this.username = profile.username || "";
        this.originalEmail = profile.email;
        this.originalPermissions = profile.permissions;
        this.isAdmin = profile.is_admin;
        this.lastLogin = this.formatTimestamp(profile.last_login);

        if (!this.userId) {
          throw new Error("Account payload did not include a user id.");
        }

        syncAdminFlag(this.isAdmin);

        this.form.email = profile.email;
        this.form.passwordCurrent = "";
        this.form.passwordNew = "";
        this.form.passwordConfirm = "";

        if (profile.username) {
          window.localStorage.setItem("username", profile.username);
        }

        this.loading = false;
      } catch (error) {
        const message =
          error instanceof Error ? error.message : "Unable to fetch account.";
        this.loadError = message;
        syncAdminFlag(false);
        this.loading = false;
      }
    },

    async submitProfile(event: Event) {
      event.preventDefault();

      this.successMessage = "";
      this.errorMessage = "";

      if (!this.userId) {
        this.errorMessage = "Missing user identifier.";
        return;
      }

      const payload: Record<string, unknown> = {};
      const trimmedEmail = this.form.email.trim();

      if (trimmedEmail && trimmedEmail !== this.originalEmail) {
        payload.email = trimmedEmail;
      }

      const hasPasswordInput =
        this.form.passwordCurrent ||
        this.form.passwordNew ||
        this.form.passwordConfirm;

      if (hasPasswordInput) {
        const passwordPayload = this.buildPasswordPayload();

        if (!passwordPayload) {
          return;
        }

        payload.password = passwordPayload;
      }

      if (Object.keys(payload).length === 0) {
        this.errorMessage = "There are no changes to save.";
        return;
      }

      try {
        const response = await fetch(`/api/users/${this.userId}`, {
          method: "PATCH",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        });

        if (!response.ok) {
          const message = await this.parseErrorResponse(response);
          throw new Error(message);
        }

        this.successMessage = "Account updated successfully.";

        if (payload.email) {
          this.originalEmail = trimmedEmail;
          this.form.email = trimmedEmail;
        }

        if (payload.password) {
          this.form.passwordCurrent = "";
          this.form.passwordNew = "";
          this.form.passwordConfirm = "";
        }
      } catch (error) {
        this.errorMessage =
          error instanceof Error ? error.message : "Update failed.";
      }
    },

    buildPasswordPayload(): PasswordPayload | null {
      const current = this.form.passwordCurrent.trim();
      const next = this.form.passwordNew.trim();
      const confirm = this.form.passwordConfirm.trim();

      if (!current || !next || !confirm) {
        this.errorMessage =
          "Please fill current, new, and confirmation password fields.";
        return null;
      }

      if (next !== confirm) {
        this.errorMessage = "New password and confirmation do not match.";
        return null;
      }

      if (!this.validatePasswordComplexity(next)) {
        this.errorMessage =
          "Password must be at least 12 characters and include uppercase, lowercase, numbers, and symbols.";
        return null;
      }

      return {
        current,
        new: next,
        confirm,
      };
    },

    validatePasswordComplexity(password: string) {
      if (password.length < 12) {
        return false;
      }

      const uppercase = /[A-Z]/.test(password);
      const lowercase = /[a-z]/.test(password);
      const digit = /\d/.test(password);
      const symbol = /[^A-Za-z0-9]/.test(password);

      return uppercase && lowercase && digit && symbol;
    },

    normalizeProfile(data: Record<string, unknown>): AccountProfile {
      const id = this.asString(data["id"] ?? data["user_id"] ?? "");
      const email = this.asString(data["email"]);
      const username = this.asString(data["username"]);

      const permissionsValue = Number(data["permissions"] ?? 0);
      const permissions = Number.isFinite(permissionsValue)
        ? permissionsValue
        : 0;

      const isAdminFlag = isAdminUser({ permissions });

      const lastLogin = this.asString(data["last_login"] ?? data["lastLogin"]);

      return {
        id,
        email,
        username,
        permissions,
        is_admin: isAdminFlag,
        last_login: lastLogin,
      };
    },

    formatTimestamp(value: string) {
      if (!value) {
        return "Never";
      }

      const date = new Date(value);

      if (Number.isNaN(date.getTime())) {
        return value;
      }

      return date.toLocaleString();
    },

    asString(value: unknown) {
      if (value === null || value === undefined) {
        return "";
      }

      return String(value);
    },

    async parseErrorResponse(response: Response) {
      const fallback = `Request failed with status ${response.status}`;

      try {
        const text = await response.text();

        if (!text) {
          return fallback;
        }

        try {
          const parsed = JSON.parse(text) as unknown;

          if (typeof parsed === "string") {
            return parsed;
          }

          if (parsed && typeof parsed === "object") {
            const record = parsed as Record<string, unknown>;
            if (record.message) {
              return this.asString(record.message);
            }
            if (record.error) {
              return this.asString(record.error);
            }
          }

          return text;
        } catch {
          return text;
        }
      } catch {
        return fallback;
      }
    },
  };
}

document.addEventListener("alpine:init", () => {
  Alpine.data("accountPage", createAccountPageState);
});
