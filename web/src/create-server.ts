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
    motdPreview: '',
    ops: '',
    cfApiKey: '',
    cfPageUrl: '',
    memoryGb: 4,
  quota: {
    loaded: false,
    unlimited: false,
    limitGi: 0,
    usedGi: 0,
    remainingGi: 0,
    overheadPercent: 0
  },
    quotaError: '',
    motdColors: [
      { code: '&0', label: '&0', color: '#000000', text: '#ffffff' },
      { code: '&1', label: '&1', color: '#0000aa', text: '#ffffff' },
      { code: '&2', label: '&2', color: '#00aa00', text: '#ffffff' },
      { code: '&3', label: '&3', color: '#00aaaa', text: '#ffffff' },
      { code: '&4', label: '&4', color: '#aa0000', text: '#ffffff' },
      { code: '&5', label: '&5', color: '#aa00aa', text: '#ffffff' },
      { code: '&6', label: '&6', color: '#ffaa00', text: '#000000' },
      { code: '&7', label: '&7', color: '#aaaaaa', text: '#000000' },
      { code: '&8', label: '&8', color: '#555555', text: '#ffffff' },
      { code: '&9', label: '&9', color: '#5555ff', text: '#ffffff' },
      { code: '&a', label: '&a', color: '#55ff55', text: '#000000' },
      { code: '&b', label: '&b', color: '#55ffff', text: '#000000' },
      { code: '&c', label: '&c', color: '#ff5555', text: '#000000' },
      { code: '&d', label: '&d', color: '#ff55ff', text: '#000000' },
      { code: '&e', label: '&e', color: '#ffff55', text: '#000000' },
      { code: '&f', label: '&f', color: '#ffffff', text: '#000000' }
    ],
    motdFormats: [
      { code: '&l', label: 'Bold', style: 'font-weight:bold;' },
      { code: '&o', label: 'Italic', style: 'font-style:italic;' },
      { code: '&n', label: 'Underline', style: 'text-decoration:underline;' },
      { code: '&m', label: 'Strike', style: 'text-decoration:line-through;' },
      { code: '&k', label: 'Obfuscate', style: 'letter-spacing:0.08em;text-shadow:0 0 6px rgba(255,255,255,0.4);' },
      { code: '&r', label: 'Reset', style: 'font-weight:normal;font-style:normal;text-decoration:none;' }
    ],
  customFields: [] as Array<{ key: string; value: string }>,
  hasError: false,
  errorMessage: '',
  isSubmitting: false,
  storageKey: 'minecharts.extraKeys',
  defaultExtraKeys: [
    'UID',
    'GID',
    'MEMORY',
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
    this.loadQuota()
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

  motdLength() {
    return this.motd?.length ?? 0
  },

  motdPreviewHtml() {
    return this.renderMotd(this.motd || '')
  },

  enforceMotdLimits() {
    if (typeof this.motd !== 'string') {
      this.motd = ''
      return
    }

    // Cap length to 59 characters (includes formatting codes)
    let value = this.motd.slice(0, 59)

    // Allow at most one newline (two lines total)
    const firstNewline = value.indexOf('\n')
    if (firstNewline !== -1) {
      const secondNewline = value.indexOf('\n', firstNewline + 1)
      if (secondNewline !== -1) {
        value = value.slice(0, secondNewline)
      }
    }

    if (value !== this.motd) {
      this.motd = value
    }
  },

  renderMotd(input: string) {
    const styles = {
      color: '',
      bold: false,
      italic: false,
      underline: false,
      strike: false,
      obfuscate: false
    }

    const colorMap: Record<string, string> = {
      '0': '#000000',
      '1': '#0000aa',
      '2': '#00aa00',
      '3': '#00aaaa',
      '4': '#aa0000',
      '5': '#aa00aa',
      '6': '#ffaa00',
      '7': '#aaaaaa',
      '8': '#555555',
      '9': '#5555ff',
      a: '#55ff55',
      b: '#55ffff',
      c: '#ff5555',
      d: '#ff55ff',
      e: '#ffff55',
      f: '#ffffff'
    }

    const escapeHtml = (value: string) =>
      value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

    const flushRun = (text: string, style: typeof styles) => {
      if (!text) return ''
      const escaped = escapeHtml(text).replace(/\n/g, '<br>')
      const decorations = []
      if (style.underline) decorations.push('underline')
      if (style.strike) decorations.push('line-through')
      const dec = decorations.length ? `text-decoration:${decorations.join(' ')};` : ''
      const obf = style.obfuscate ? 'letter-spacing:0.08em;text-shadow:0 0 6px rgba(255,255,255,0.4);' : ''
      const fontWeight = style.bold ? 'font-weight:bold;' : ''
      const fontStyle = style.italic ? 'font-style:italic;' : ''
      const color = style.color ? `color:${style.color};` : ''
      return `<span style="${color}${fontWeight}${fontStyle}${dec}${obf}">${escaped}</span>`
    }

    let result = ''
    let buffer = ''

    const reset = () => {
      styles.color = ''
      styles.bold = false
      styles.italic = false
      styles.underline = false
      styles.strike = false
      styles.obfuscate = false
    }

    for (let i = 0; i < input.length; i += 1) {
      const ch = input[i]
      if (ch === '&' && i + 1 < input.length) {
        const code = input[i + 1].toLowerCase()
        if (colorMap[code]) {
          result += flushRun(buffer, styles)
          buffer = ''
          styles.color = colorMap[code]
          i += 1
          continue
        }

        if ('loni'.includes(code) || code === 'm' || code === 'k' || code === 'r') {
          result += flushRun(buffer, styles)
          buffer = ''
          switch (code) {
            case 'l':
              styles.bold = true
              break
            case 'o':
              styles.italic = true
              break
            case 'n':
              styles.underline = true
              break
            case 'm':
              styles.strike = true
              break
            case 'k':
              styles.obfuscate = true
              break
            case 'r':
              reset()
              break
          }
          i += 1
          continue
        }
      }
      buffer += ch
    }

    result += flushRun(buffer, styles)
    return result || '<span class="text-zinc-500">Preview</span>'
  },

  insertMotdToken(token: string) {
    const el = this.$refs.motdInput as HTMLTextAreaElement | undefined
    if (!el) return
    const start = el.selectionStart ?? this.motd.length
    const end = el.selectionEnd ?? this.motd.length
    const value = this.motd || ''
    this.motd = value.slice(0, start) + token + value.slice(end)
    this.$nextTick(() => {
      const pos = start + token.length
      el.focus()
      el.setSelectionRange(pos, pos)
    })
  },

  insertMotdChar(char: string) {
    this.insertMotdToken(char)
  },

  buildEnv() {
    const env: Record<string, string> = {}

    env.TYPE = this.serverType
    if (this.serverType === 'VANILLA') {
      env.VERSION = this.version
    }

    const memory = this.validMemory()
    if (memory > 0) {
      env.MEMORY = `${memory}G`
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

  validMemory() {
    if (!Number.isFinite(this.memoryGb)) return 0
    if (this.memoryGb <= 0) return 0
    return Math.floor(this.memoryGb)
  },

  overheadGi() {
    const mem = this.validMemory()
    if (mem <= 0) return 0
    const overhead = this.quota.overheadPercent ?? 0
    if (!Number.isFinite(overhead) || overhead < 0) return 0
    return (mem * overhead) / 100
  },

  totalGi() {
    return this.validMemory() + this.overheadGi()
  },

  fitsQuota() {
    if (this.quota.unlimited || !this.quota.loaded) return true
    return this.totalGi() <= this.quota.remainingGi + 1e-9
  },

  async loadQuota() {
    try {
      const response = await fetch('/api/quota/memory')
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      const payload = (await response.json()) as {
        unlimited?: boolean
        limitGi?: number
        usedGi?: number
        remainingGi?: number
        overheadPercent?: number
      }
      this.quota = {
        loaded: true,
        unlimited: payload?.unlimited ?? false,
        limitGi: payload?.limitGi ?? 0,
        usedGi: payload?.usedGi ?? 0,
        remainingGi: payload?.remainingGi ?? 0,
        overheadPercent: payload?.overheadPercent ?? 0
      }
      this.quotaError = ''
    } catch (err) {
      this.quota.loaded = false
      this.quotaError = 'Unable to load memory quota. Values may be inaccurate.'
    }
  },

  formatGi(value: number) {
    if (!Number.isFinite(value)) return '0'
    return value % 1 === 0 ? `${value} Gi` : `${value.toFixed(2)} Gi`
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
          if (latestRelease && item.id === latestRelease) return
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
