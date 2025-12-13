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

function renderAdminWarningsBanner(warnings: AdminWarning[]) {
    if (typeof document === 'undefined') return
    if (!Array.isArray(warnings) || warnings.length === 0) return

    // Remove existing banner before re-rendering
    const existing = document.getElementById(ADMIN_WARNINGS_BANNER_ID)
    if (existing?.parentElement) {
        existing.parentElement.removeChild(existing)
    }

    const container = document.createElement('div')
    container.id = ADMIN_WARNINGS_BANNER_ID
    container.className = 'fixed bottom-4 left-4 right-4 z-50 flex justify-center px-4'

    const panel = document.createElement('div')
    panel.className =
        'w-full max-w-4xl rounded-lg border border-amber-500/60 bg-amber-950/80 text-amber-50 shadow-lg backdrop-blur-sm'

    const header = document.createElement('div')
    header.className = 'flex items-center justify-between px-4 py-2 border-b border-amber-700/60'
    const title = document.createElement('span')
    title.className = 'font-semibold text-sm tracking-wide'
    title.textContent = 'Configuration warnings'
    const close = document.createElement('button')
    close.type = 'button'
    close.className =
        'text-amber-100 hover:text-white rounded px-2 py-1 text-sm transition-colors hover:bg-amber-800/60'
    close.textContent = 'Dismiss'
    close.addEventListener('click', () => {
        const el = document.getElementById(ADMIN_WARNINGS_BANNER_ID)
        el?.remove()
    })
    header.appendChild(title)
    header.appendChild(close)

    const list = document.createElement('ul')
    list.className = 'px-4 py-3 space-y-2 text-sm'

    warnings.forEach((warning) => {
        const li = document.createElement('li')
        li.className = 'flex items-start gap-2'
        const bullet = document.createElement('span')
        bullet.className = 'mt-1 h-2 w-2 rounded-full bg-amber-400 flex-shrink-0'
        const text = document.createElement('div')
        const code = warning.code ? `[${warning.code}] ` : ''
        text.textContent = `${code}${warning.message ?? ''}`
        li.appendChild(bullet)
        li.appendChild(text)
        list.appendChild(li)
    })

    panel.appendChild(header)
    panel.appendChild(list)
    container.appendChild(panel)
    document.body.appendChild(container)
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
