import Alpine from "alpinejs";
import { fetchAuthInfo, isAdminUser, syncAdminFlag } from "./main";

type RawUser = Record<string, unknown>;

type AdminUserEntry = {
  id: string;
  username: string;
  email: string;
  permissions: number;
  active: boolean;
  lastLogin: string;
  createdAt: string;
  updatedAt: string;
  permissionsDraft: number;
  busy: boolean;
  message: string;
  error: string;
};

type AccountProfile = {
  id: string;
  username: string;
  permissions: number;
  is_admin: boolean;
};

declare global {
  interface Window {
    adminPanel?: ReturnType<typeof createAdminPanelState>;
  }
}

const PERMISSION_FLAGS = [
  { bit: 1 << 0, label: "Administrator" },
  { bit: 1 << 1, label: "Create server" },
  { bit: 1 << 2, label: "Delete server" },
  { bit: 1 << 3, label: "Start server" },
  { bit: 1 << 4, label: "Stop server" },
  { bit: 1 << 5, label: "Restart server" },
  { bit: 1 << 6, label: "Execute command" },
  { bit: 1 << 7, label: "View server" },
] as const;

function createAdminPanelState() {
  return {
    loading: true,
    loadError: "",
    isAdmin: false,
    profile: null as AccountProfile | null,
    users: [] as AdminUserEntry[],
    usersLoading: false,
    usersError: "",
    permissionOptions: PERMISSION_FLAGS,
    createForm: {
      username: "",
      email: "",
      password: "",
      confirm: "",
      busy: false,
      message: "",
      error: "",
    },

    init() {
      this.bootstrap();
    },

    async bootstrap() {
      this.loading = true;
      this.loadError = "";

      try {
        const auth = await fetchAuthInfo();

        if (!auth) {
          throw new Error("Authentication required.");
        }

        const profile = this.normalizeProfile(auth as RawUser);

        if (!profile.is_admin) {
          syncAdminFlag(false);
          this.loadError = "Permission denied.";
          this.loading = false;
          setTimeout(() => {
            window.location.replace("/account.html");
          }, 150);
          return;
        }

        syncAdminFlag(true);
        this.profile = profile;
        this.isAdmin = profile.is_admin;
        this.resetCreateForm();
        await this.loadUsers();
      } catch (error) {
        this.loadError =
          error instanceof Error ? error.message : "Unable to load admin panel.";
        syncAdminFlag(false);
      } finally {
        this.loading = false;
      }
    },

    async loadUsers() {
      this.usersLoading = true;
      this.usersError = "";

      try {
        const response = await fetch("/api/users", {
          credentials: "include",
        });

        if (!response.ok) {
          const message = await this.parseErrorResponse(response);
          throw new Error(message || "Could not load users list.");
        }

        const data = (await response.json()) as unknown;

        if (!Array.isArray(data)) {
          throw new Error("Unexpected users response format.");
        }

        this.users = data
          .map((entry) => this.normalizeUser(entry))
          .filter((user): user is AdminUserEntry => Boolean(user.id));
      } catch (error) {
        this.usersError =
          error instanceof Error ? error.message : "Could not load users list.";
        this.users = [];
      } finally {
        this.usersLoading = false;
      }
    },

    resetCreateForm() {
      this.createForm.username = "";
      this.createForm.email = "";
      this.createForm.password = "";
      this.createForm.confirm = "";
      this.createForm.busy = false;
      this.createForm.message = "";
      this.createForm.error = "";
    },

    async createUser(event: Event) {
      event.preventDefault();

      if (!this.isAdmin) {
        this.createForm.error = "You are not allowed to create users.";
        return;
      }

      if (this.createForm.busy) {
        return;
      }

      const username = this.createForm.username.trim();
      const email = this.createForm.email.trim();
      const password = this.createForm.password;
      const confirm = this.createForm.confirm;
      if (!username) {
        this.createForm.error = "Username is required.";
        return;
      }

      if (!email) {
        this.createForm.error = "Email is required.";
        return;
      }

      if (!password || !confirm) {
        this.createForm.error = "Password and confirmation are required.";
        return;
      }

      if (password !== confirm) {
        this.createForm.error = "Passwords do not match.";
        return;
      }

      this.createForm.busy = true;
      this.createForm.error = "";
      this.createForm.message = "";

      try {
        const registerResponse = await fetch("/api/auth/register", {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username,
            email,
            password,
          }),
        });

        if (!registerResponse.ok) {
          const message = await this.parseErrorResponse(registerResponse);
          throw new Error(message || "User registration failed.");
        }

        let newUser: AdminUserEntry | null = null;

        try {
          const payload = (await registerResponse.json()) as RawUser | { user?: RawUser };
          const record = (payload && typeof payload === "object" && "user" in payload && payload.user)
            ? (payload as { user: RawUser }).user
            : (payload as RawUser);
          newUser = this.normalizeUser(record);
        } catch {
          newUser = null;
        }

        this.createForm.message = "User created successfully.";
        this.resetCreateForm();

        if (newUser) {
          this.users = [newUser, ...this.users];
        } else {
          await this.loadUsers();
        }
      } catch (error) {
        this.createForm.error =
          error instanceof Error ? error.message : "Unable to create user.";
      } finally {
        this.createForm.busy = false;
      }
    },

    formatPermissionSummary(user: AdminUserEntry) {
      const activeFlags = this.permissionOptions.filter((option) =>
        this.hasPermission(user, option.bit),
      );

      if (activeFlags.length === 0) {
        return "No permissions";
      }

      if (activeFlags.length === this.permissionOptions.length) {
        return "All permissions";
      }

      return activeFlags.map((option) => option.label).join(", ");
    },

    hasPermission(user: AdminUserEntry, bit: number) {
      return (user.permissionsDraft & bit) === bit;
    },

    togglePermission(user: AdminUserEntry, bit: number) {
      if (this.isSelf(user)) {
        user.error = "You cannot change your own permissions.";
        return;
      }

      user.permissionsDraft ^= bit;
      user.error = "";
      user.message = "Unsaved changes";
    },

    permissionsChanged(user: AdminUserEntry) {
      return user.permissionsDraft !== user.permissions;
    },

    async savePermissions(user: AdminUserEntry) {
      if (!this.permissionsChanged(user)) {
        user.message = "No changes.";
        return;
      }

      await this.updateUser(user, { permissions: user.permissionsDraft }, () => {
        user.permissions = user.permissionsDraft;
        user.message = "Permissions updated.";
      });
    },

    async toggleActive(user: AdminUserEntry) {
      if (this.isSelf(user)) {
        user.error = "You cannot change your own status.";
        return;
      }

      const targetState = !user.active;
      const label = targetState ? "activate" : "deactivate";

      if (
        !window.confirm(
          `Are you sure you want to ${label} ${user.username || user.email || user.id}?`,
        )
      ) {
        return;
      }

      await this.updateUser(user, { active: targetState }, () => {
        user.active = targetState;
        user.message = targetState ? "User activated." : "User deactivated.";
      });
    },

    async deleteUser(user: AdminUserEntry) {
      if (this.isSelf(user)) {
        user.error = "You cannot delete your own account.";
        return;
      }

      if (user.active) {
        user.error = "Deactivate the user before deleting.";
        return;
      }

      if (!window.confirm(`Delete ${user.username || user.email || user.id}?`)) {
        return;
      }

      user.busy = true;
      user.error = "";
      user.message = "";

      try {
        const response = await fetch(`/api/users/${user.id}`, {
          method: "DELETE",
          credentials: "include",
        });

        if (!response.ok) {
          const message = await this.parseErrorResponse(response);
          throw new Error(message);
        }

        this.users = this.users.filter((entry) => entry.id !== user.id);
      } catch (error) {
        user.error = error instanceof Error ? error.message : "Unable to delete user.";
      } finally {
        user.busy = false;
      }
    },

    async updateUser(
      user: AdminUserEntry,
      payload: Record<string, unknown>,
      onSuccess: () => void,
    ) {
      user.busy = true;
      user.error = "";
      user.message = "";

      try {
        const response = await fetch(`/api/users/${user.id}`, {
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

        onSuccess();
      } catch (error) {
        user.error = error instanceof Error ? error.message : "Update failed.";
        user.permissionsDraft = user.permissions;
      } finally {
        user.busy = false;
      }
    },

    isSelf(user: AdminUserEntry) {
      return this.profile && this.profile.id === user.id;
    },

    normalizeProfile(raw: RawUser): AccountProfile {
      const id = this.asString(raw["id"] ?? raw["user_id"] ?? "");
      const username = this.asString(raw["username"]);
      const permissions = Number(raw["permissions"] ?? 0) || 0;
      const isAdmin = isAdminUser({ permissions });

      return {
        id,
        username,
        permissions,
        is_admin: isAdmin,
      };
    },

    normalizeUser(raw: unknown): AdminUserEntry {
      if (!raw || typeof raw !== "object") {
        return {
          id: "",
          username: "",
          email: "",
          permissions: 0,
          active: false,
          lastLogin: "",
          createdAt: "",
          updatedAt: "",
          permissionsDraft: 0,
          busy: false,
          message: "",
          error: "",
        };
      }

      const record = raw as RawUser;
      const permissions = Number(record["permissions"] ?? 0) || 0;

      return {
        id: this.asString(record["id"] ?? record["user_id"] ?? ""),
        username: this.asString(record["username"]),
        email: this.asString(record["email"]),
        permissions,
        active: Boolean(record["active"]),
        lastLogin: this.asString(record["last_login"] ?? record["lastLogin"]),
        createdAt: this.asString(record["created_at"] ?? record["createdAt"]),
        updatedAt: this.asString(record["updated_at"] ?? record["updatedAt"]),
        permissionsDraft: permissions,
        busy: false,
        message: "",
        error: "",
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
            const record = parsed as RawUser;
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

Alpine.data("adminPanel", createAdminPanelState);
