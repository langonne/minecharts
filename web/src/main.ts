import Alpine from 'alpinejs'
import collapse from '@alpinejs/collapse'
import htmx from 'htmx.org'
import 'virtual:uno.css'
import './styles.css'
import './feedback'

declare global {
    interface Window {
        Alpine: typeof Alpine
        htmx: typeof htmx
        __authCache?: AuthCache
    }
}

type AuthInfo = {
    id?: number | string
    user_id?: number | string
    username?: string
    email?: string
    permissions?: number
    admin_warnings_enabled?: boolean
    [key: string]: unknown
}

type AuthCache = {
    promise: Promise<AuthInfo | null>
    timestamp: number
}

type AdminWarning = {
    code?: string
    message?: string
}

const PERM_ADMIN_FLAG = 1 << 0 // aligns with backend PermAdmin bit
const USERNAME_CHANGE_EVENT = 'auth:username-change'
const ADMIN_CHANGE_EVENT = 'auth:admin-change'
const ADMIN_WARNINGS_BANNER_ID = 'admin-warnings-banner'
const ADMIN_WARNINGS_SEEN_KEY = 'admin_warnings_seen'
const ADMIN_WARNING_TIMEOUT_MS = 10_000

function emitUsernameChange(username: string | null) {
    if (typeof document === 'undefined') {
        return
    }

    document.dispatchEvent(
        new CustomEvent(USERNAME_CHANGE_EVENT, {
            detail: { username },
        }),
    )
}

function emitAdminChange(isAdmin: boolean) {
    if (typeof document === 'undefined') {
        return
    }

    document.dispatchEvent(
        new CustomEvent(ADMIN_CHANGE_EVENT, {
            detail: { isAdmin },
        }),
    )
}

function syncUsername(username: unknown) {
    const value =
        typeof username === 'string' ? username.trim() : ''
    const normalized = value.length > 0 ? value : null

    if (normalized) {
        localStorage.setItem('username', normalized)
    } else {
        localStorage.removeItem('username')
    }

    emitUsernameChange(normalized)
}

function syncAdminFlag(isAdmin: boolean) {
    if (isAdmin) {
        localStorage.setItem('is_admin', 'true')
    } else {
        localStorage.removeItem('is_admin')
    }

    emitAdminChange(isAdmin)
}

function isAdminUser(info: { permissions?: unknown } | null): boolean {
    const permissions = Number(info?.permissions ?? 0)
    if (!Number.isFinite(permissions)) {
        return false
    }
    return (permissions & PERM_ADMIN_FLAG) === PERM_ADMIN_FLAG
}

function updateAdminFlag(info: AuthInfo | null) {
    const isAdmin = isAdminUser(info)
    syncAdminFlag(isAdmin)
}

let adminWarningsAttempted = false

function warningsFingerprint(warnings: AdminWarning[]): string {
    if (!Array.isArray(warnings) || warnings.length === 0) return ''
    const parts = warnings.map((w) => `${w.code ?? ''}|${w.message ?? ''}`)
    parts.sort()
    return parts.join('||')
}

function renderAdminWarningsBanner(warnings: AdminWarning[]) {
    if (typeof document === 'undefined') return
    if (!Array.isArray(warnings) || warnings.length === 0) return

    const fingerprint = warningsFingerprint(warnings)
    if (fingerprint) {
        const seen = sessionStorage.getItem(ADMIN_WARNINGS_SEEN_KEY)
        if (seen === fingerprint) {
            return
        }
    }

    // Remove existing banner before re-rendering
    const existing = document.getElementById(ADMIN_WARNINGS_BANNER_ID)
    if (existing?.parentElement) {
        existing.parentElement.removeChild(existing)
    }

    const container = document.createElement('div')
    container.id = ADMIN_WARNINGS_BANNER_ID
    container.style.position = 'fixed'
    container.style.bottom = '1rem'
    container.style.right = '1rem'
    container.style.zIndex = '9999'
    container.style.display = 'flex'
    container.style.flexDirection = 'column'
    container.style.gap = '0.5rem'
    container.style.maxWidth = '24rem'
    container.style.width = 'calc(100% - 2rem)'

    warnings.forEach((warning) => {
        const card = document.createElement('div')
        card.style.background = '#1f2937'
        card.style.color = '#fef3c7'
        card.style.border = '1px solid rgba(251, 191, 36, 0.35)'
        card.style.borderLeft = '4px solid #fbbf24'
        card.style.borderRadius = '8px'
        card.style.boxShadow = '0 10px 25px rgba(0,0,0,0.25)'
        card.style.padding = '0.75rem 0.9rem'
        card.style.display = 'flex'
        card.style.alignItems = 'flex-start'
        card.style.gap = '0.5rem'
        card.style.position = 'relative'

        const icon = document.createElement('span')
        icon.textContent = '⚠️'
        icon.setAttribute('aria-hidden', 'true')
        icon.style.fontSize = '1rem'
        icon.style.marginTop = '2px'

        const textWrap = document.createElement('div')
        const code = warning.code ? `[${warning.code}] ` : ''
        textWrap.textContent = `${code}${warning.message ?? ''}`
        textWrap.style.fontSize = '0.9rem'
        textWrap.style.lineHeight = '1.4'

        const close = document.createElement('button')
        close.type = 'button'
        close.textContent = '×'
        close.style.marginLeft = 'auto'
        close.style.fontSize = '1rem'
        close.style.color = '#fef3c7'
        close.style.background = 'transparent'
        close.style.border = 'none'
        close.style.cursor = 'pointer'
        close.style.padding = '0 0.2rem'
        close.addEventListener('click', () => {
            card.remove()
            if (!container.hasChildNodes()) {
                container.remove()
            }
        })

        card.appendChild(icon)
        card.appendChild(textWrap)
        card.appendChild(close)
        container.appendChild(card)

        // Auto-dismiss after timeout
        const timeout = setTimeout(() => {
            card.remove()
            if (!container.hasChildNodes()) {
                container.remove()
            }
        }, ADMIN_WARNING_TIMEOUT_MS)

        close.addEventListener('click', () => clearTimeout(timeout))
    })

    document.body.appendChild(container)

    if (fingerprint) {
        sessionStorage.setItem(ADMIN_WARNINGS_SEEN_KEY, fingerprint)
    }
}

async function maybeLoadAdminWarnings(info: AuthInfo | null) {
    if (adminWarningsAttempted) return
    if (!info || !isAdminUser(info)) return
    if (!info.admin_warnings_enabled) return

    adminWarningsAttempted = true
    try {
        const response = await fetch('/api/admin/warnings', { credentials: 'include' })
        if (!response.ok) return
        const payload = (await response.json()) as { warnings?: AdminWarning[] } | null
        if (payload?.warnings && payload.warnings.length > 0) {
            renderAdminWarningsBanner(payload.warnings)
        }
    } catch {
        /* ignore fetch errors */
    }
}

window.Alpine = Alpine
window.htmx = htmx
Alpine.plugin(collapse)
queueMicrotask(() => Alpine.start())
    ; (async () => {
        // @ts-ignore
        await import('htmx.org/dist/ext/json-enc.js')
    })()

function broadcastStoredAuthState() {
    const storedUsername = localStorage.getItem('username')
    const storedAdmin = localStorage.getItem('is_admin') === 'true'
    emitUsernameChange(storedUsername)
    emitAdminChange(storedAdmin)
}

if (typeof document !== 'undefined') {
    document.addEventListener('htmx:afterSwap', (event) => {
        const detail = (event as CustomEvent).detail ?? {}
        const path =
            typeof detail.requestConfig?.path === 'string'
                ? detail.requestConfig.path
                : typeof detail.xhr?.responseURL === 'string'
                    ? detail.xhr.responseURL
                    : ''

        if (path.includes('navbar.html')) {
            broadcastStoredAuthState()
        }
    })
}

if (typeof window !== 'undefined') {
    window.addEventListener('load', () => {
        broadcastStoredAuthState()
    })
}

function storeAuthResponse(data: AuthInfo | null) {
    syncUsername(data?.username ?? null)
    window.__authCache = {
        promise: Promise.resolve(data),
        timestamp: Date.now(),
    }
}

async function fetchAuthInfo(): Promise<AuthInfo | null> {
    if (window.__authCache) {
        const data = await window.__authCache.promise
        maybeLoadAdminWarnings(data)
        return data
    }

    const promise = (async () => {
        try {
            const response = await fetch('/api/auth/me', {
                credentials: 'include'
            })

            if (!response.ok) {
                syncUsername(null)
                updateAdminFlag(null)
                maybeLoadAdminWarnings(null)
                return null
            }

            const data = await response.json() as AuthInfo
            updateAdminFlag(data)
            syncUsername(data.username)
            maybeLoadAdminWarnings(data)
            return data
        } catch {
            syncUsername(null)
            updateAdminFlag(null)
            maybeLoadAdminWarnings(null)
            return null
        }
    })()

    window.__authCache = {
        promise,
        timestamp: Date.now(),
    }

    return promise
}

function getRouteAccess(): 'public' | 'private' | 'guest' {
    const meta = document.querySelector('meta[name="route:access"]') as HTMLMetaElement | null;
    const val = meta?.content?.toLowerCase();
    if (val === 'private' || val === 'guest') return val;
    return 'public';
}

function revealBody() {
    document.body.style.setProperty('opacity', '1');
}

function redirect(url: string) {
    window.location.replace(url);
}

(async function routeGuard() {
    const access = getRouteAccess();
    const requireAdmin = document.body?.dataset?.requireAdmin === 'true';

    if (access === 'public') {
        revealBody();
        updateAdminFlag(null)
        return;
    }

    const authInfo = await fetchAuthInfo();
    const logged = Boolean(authInfo);
    const isAdmin = isAdminUser(authInfo);

    if (access === 'guest') {
        if (logged) redirect('/dashboard.html');
        else revealBody();
        return;
    }

    // private
    if (!logged) {
        redirect('/login.html');
        return;
    }

    if (requireAdmin && !isAdmin) {
        updateAdminFlag(authInfo ?? null)
        redirect('/account.html');
        return;
    }

    revealBody();
    if (authInfo) {
        storeAuthResponse(authInfo)
        updateAdminFlag(authInfo)
    }
})();

export { fetchAuthInfo, isAdminUser, syncAdminFlag };
