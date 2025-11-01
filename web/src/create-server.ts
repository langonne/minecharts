import Alpine from 'alpinejs'

type SelectOption = {
  value: string
  label: string
}

type VersionManifest = {
  latest?: {
    release?: string
  }
  versions?: Array<{
    id?: string
    type?: string
  }>
}

Alpine.data('createServerForm', () => ({
    serverName: '',
    version: '1.21.1',
    serverType: 'VANILLA',
    gameMode: 'survival',
    difficulty: 'peaceful',
    maxPlayers: 10,
    motd: '',
    ops: '',
    cfApiKey: '',
    cfPageUrl: '',
    customFields: [] as Array<{ key: string; value: string }>,
    hasError: false,
    errorMessage: '',
    isSubmitting: false,
    storageKey: 'minecharts.extraKeys',
    defaultExtraKeys: [
      'UID',
      'GID',
      'MAX_MEMORY',
      'MAX_WORLD_SIZE',
      'ALLOW_NETHER',
      'ANNOUNCE_PLAYER_ACHIEVEMENTS',
      'ENABLE_COMMAND_BLOCK',
      'FORCE_GAMEMODE',
      'GENERATE_STRUCTURES',
      'HARDCORE',
      'MAX_BUILD_HEIGHT',
      'SPAWN_ANIMALS',
      'SPAWN_MONSTERS',
      'SPAWN_NPCS',
      'SPAWN_PROTECTION',
      'VIEW_DISTANCE',
      'SEED',
      'PVP',
      'LEVEL_TYPE',
      'GENERATOR_SETTINGS',
      'LEVEL',
      'ONLINE_MODE',
      'ALLOW_FLIGHT',
      'PLAYER_IDLE_TIMEOUT',
      'RESOURCE_PACK',
      'RESOURCE_PACK_SHA1',
      'RESOURCE_PACK_ENFORCE',
      'ENABLE_WHITELIST',
      'WHITELIST',
      'WHITELIST_FILE',
      'OVERRIDE_WHITELIST',
      'CF_API_KEY',
      'CF_API_KEY_FILE',
      'CF_PAGE_URL',
      'CF_SLUG',
      'CF_FILE_ID',
      'CF_FILENAME_MATCHER',
      'CF_EXCLUDE_INCLUDE_FILE',
      'CF_EXCLUDE_MODS',
      'CF_FORCE_INCLUDE_MODS',
      'CF_FORCE_SYNCHRONIZE',
      'CF_SET_LEVEL_FROM'
    ],
    knownKeys: [] as string[],
    versionManifestUrl: 'https://launchermeta.mojang.com/mc/game/version_manifest_v2.json',
    versions: [
      { value: 'LATEST', label: 'Latest stable' },
      { value: '1.21.1', label: '1.21.1' },
      { value: '1.20.4', label: '1.20.4' },
      { value: '1.19.4', label: '1.19.4' }
    ] as SelectOption[],
    serverTypes: [
      { value: 'VANILLA', label: 'Vanilla' },
      { value: 'AUTO_CURSEFORGE', label: 'Modpack (CurseForge)' }
    ] as SelectOption[],
    gameModes: [
      { value: 'survival', label: 'Survival' },
      { value: 'creative', label: 'Creative' },
      { value: 'adventure', label: 'Adventure' }
    ] as SelectOption[],
    difficulties: [
      { value: 'peaceful', label: 'Peaceful' },
      { value: 'easy', label: 'Easy' },
      { value: 'normal', label: 'Normal' },
      { value: 'hard', label: 'Hard' }
    ] as SelectOption[],

    init() {
      this.bootstrapKnownKeys()
      this.ensureTrailingField()
      this.loadVersions()
      this.$nextTick(() => {
        this.$el.addEventListener('htmx:beforeRequest', () => {
          this.handleBeforeRequest()
        })

        this.$el.addEventListener('htmx:afterRequest', (event: Event) => {
          this.handleAfterRequest(event as CustomEvent)
        })
      })
    },

    bootstrapKnownKeys() {
      let persisted: string[] = []
      try {
        const stored = localStorage.getItem(this.storageKey)
        if (stored) {
          const parsed = JSON.parse(stored)
          if (Array.isArray(parsed)) {
            persisted = parsed.filter((item) => typeof item === 'string')
          }
        }
      } catch {
        persisted = []
      }

      const merged = Array.from(new Set([...this.defaultExtraKeys, ...persisted]))
      this.knownKeys = merged.sort()
    },

    registerKey(rawKey: string) {
      const key = this.normalizeEnvKey(rawKey)
      if (!key) return

      if (!this.knownKeys.includes(key)) {
        this.knownKeys.push(key)
        this.knownKeys.sort()
        this.persistKnownKeys()
      }
    },

    persistKnownKeys() {
      const customOnly = this.knownKeys.filter((item) => !this.defaultExtraKeys.includes(item))
      localStorage.setItem(this.storageKey, JSON.stringify(customOnly))
    },

    ensureTrailingField() {
      const last = this.customFields[this.customFields.length - 1]
      if (!last || (last.key.trim() !== '' || last.value.trim() !== '')) {
        this.customFields.push({ key: '', value: '' })
      }
    },

    onFieldChange(index: number) {
      const field = this.customFields[index]
      if (!field) return

      const key = field.key
      const value = field.value.trim()

      const isEmpty = key.trim() === '' && value === ''
      const isComplete = key.trim() !== '' && value !== ''

      if (isEmpty) {
        this.customFields.splice(index, 1)
        this.ensureTrailingField()
        return
      }

      if (isComplete) {
        const normalizedKey = this.normalizeEnvKey(key)
        if (normalizedKey) {
          this.customFields[index].key = normalizedKey
          this.registerKey(normalizedKey)
        }
        this.ensureTrailingField()
        return
      }

      // Partial input: ensure there is always one trailing empty row
      if (index === this.customFields.length - 1) {
        this.ensureTrailingField()
      }
    },

    normalizeEnvKey(rawKey: string) {
      return rawKey
        .trim()
        .replace(/[\s-]+/g, '_')
        .replace(/[^A-Za-z0-9_]/g, '')
        .toUpperCase()
    },

    filteredCustomFields() {
      return this.customFields.filter((field) => field.key.trim() !== '' && field.value.trim() !== '')
    },

    buildEnv() {
      const env: Record<string, string> = {}

      env.TYPE = this.serverType
      if (this.serverType === 'VANILLA') {
        env.VERSION = this.version
      }

      if (this.serverType === 'AUTO_CURSEFORGE') {
        const apiKey = this.cfApiKey.trim()
        const pageUrl = this.cfPageUrl.trim()

        if (apiKey) {
          env.CF_API_KEY = apiKey
        }

        if (pageUrl) {
          env.CF_PAGE_URL = pageUrl
        }
      }

      env.MODE = this.gameMode.toUpperCase()
      env.DIFFICULTY = this.difficulty.toUpperCase()

      if (Number.isFinite(this.maxPlayers) && this.maxPlayers > 0) {
        env.MAX_PLAYERS = String(this.maxPlayers)
      }

      if (this.motd.trim()) {
        env.MOTD = this.motd.trim()
      }

      if (this.ops.trim()) {
        const list = this.ops
          .split(',')
          .map((entry) => entry.trim())
          .filter(Boolean)
          .join(',')
        if (list) {
          env.OPS = list
        }
      }

      this.filteredCustomFields().forEach((field) => {
        const key = this.normalizeEnvKey(field.key)
        const value = field.value.trim()

        if (!key || !value) return
        env[key] = value
      })

      return env
    },

    async loadVersions() {
      try {
        const response = await fetch(this.versionManifestUrl)
        if (!response.ok) return

        const payload = (await response.json()) as VersionManifest | null
        const latestRelease = payload?.latest?.release
        const entries = Array.isArray(payload?.versions) ? payload.versions : []
        const releases = entries.filter((item) => item?.type === 'release')

        const options: SelectOption[] = []
        if (latestRelease) {
          options.push({ value: 'LATEST', label: `Latest release (${latestRelease})` })
        }

        releases.forEach((item) => {
          if (!item?.id) return
          options.push({ value: item.id, label: item.id })
        })

        if (options.length > 0) {
          this.versions = options
          if (latestRelease) {
            this.version = latestRelease
          }
        }
      } catch {
        /* ignore network failures and keep fallback */
      }
    },

    buildPayload() {
      return {
        serverName: this.serverName.trim(),
        env: this.buildEnv()
      }
    },

    hxPayload() {
      return `js:${JSON.stringify(this.buildPayload())}`
    },

    clearError() {
      this.hasError = false
      this.errorMessage = ''
    },

    handleBeforeRequest() {
      this.isSubmitting = true
      this.clearError()
    },

    handleAfterRequest(event?: CustomEvent) {
      const detail = event?.detail
      if (!detail) {
        this.isSubmitting = false
        return
      }
      this.isSubmitting = false

      if (detail.successful) {
        window.location.href = '/dashboard.html'
        return
      }

      this.hasError = true

      try {
        const xhr = detail.xhr
        const response = xhr?.responseText ? JSON.parse(xhr.responseText) : null
        this.errorMessage = response?.error ?? 'An error occurred.'
      } catch {
        this.errorMessage = 'An error occurred.'
      }
    }
  }))
