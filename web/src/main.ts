import Alpine from 'alpinejs'
import collapse from '@alpinejs/collapse'
import htmx from 'htmx.org'
import 'virtual:uno.css'
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
    [key: string]: unknown
}

type AuthCache = {
    promise: Promise<AuthInfo | null>
    timestamp: number
}

const MIN_ADMIN_PERMISSIONS = 128

function syncAdminFlag(isAdmin: boolean) {
    if (isAdmin) {
        localStorage.setItem('is_admin', 'true')
    } else {
        localStorage.removeItem('is_admin')
    }

    if (typeof document !== 'undefined') {
        document.dispatchEvent(
            new CustomEvent('auth:admin-change', {
                detail: { isAdmin },
            }),
        )
    }
}

function isAdminUser(info: { permissions?: unknown } | null): boolean {
    const permissions = Number(info?.permissions ?? 0)
    return Number.isFinite(permissions) && permissions >= MIN_ADMIN_PERMISSIONS
}

function updateAdminFlag(info: AuthInfo | null) {
    const isAdmin = isAdminUser(info)
    syncAdminFlag(isAdmin)
}

window.Alpine = Alpine
window.htmx = htmx
Alpine.plugin(collapse)
queueMicrotask(() => Alpine.start())
    ; (async () => {
        // @ts-ignore
        await import('htmx.org/dist/ext/json-enc.js')
    })()

function storeAuthResponse(data: AuthInfo | null) {
    window.__authCache = {
        promise: Promise.resolve(data),
        timestamp: Date.now(),
    }
}

async function fetchAuthInfo(): Promise<AuthInfo | null> {
    if (window.__authCache) {
        return window.__authCache.promise
    }

    const promise = (async () => {
        try {
            const response = await fetch('/api/auth/me', {
                credentials: 'include'
            })

            if (!response.ok) {
                return null
            }

            const data = await response.json() as AuthInfo
            updateAdminFlag(data)
            return data
        } catch {
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
