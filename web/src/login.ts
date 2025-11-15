import Alpine from 'alpinejs'

type OAuthProvidersPayload = {
  providers?: Array<{ name: string }>
}

const AUTHENTIK_PROVIDER_NAME = 'authentik'
const authentikEnvDefault = import.meta.env.VITE_AUTHENTIK_LOGIN_ENABLED === 'true'

Alpine.data('loginForm', () => ({
  hasError: false,
  errorMessage: '',
  authentikLoginEnabled: authentikEnvDefault,

  init() {
    this.$el.addEventListener('htmx:afterRequest', (event) => {
      const { detail } = event as CustomEvent<{ successful: boolean; xhr: XMLHttpRequest }>
      const xhr = detail.xhr

      if (detail.successful) {
        const jsonResponse = JSON.parse(xhr.responseText)
        localStorage.setItem('username', jsonResponse.username)
        window.location.href = '/dashboard.html'
      } else {
        this.hasError = true
        try {
          const jsonResponse = JSON.parse(xhr.responseText)
          this.errorMessage = jsonResponse.error
        } catch {
          this.errorMessage = 'An error has occurred'
        }
      }
    })

    this.refreshOAuthProviders()
  },

  async refreshOAuthProviders() {
    try {
      const response = await fetch('/api/auth/providers', {
        headers: {
          Accept: 'application/json',
        },
      })

      if (!response.ok) {
        return
      }

      const payload = (await response.json()) as OAuthProvidersPayload
      const providers = Array.isArray(payload.providers) ? payload.providers : []
      this.authentikLoginEnabled = providers.some(
        (provider) => provider.name === AUTHENTIK_PROVIDER_NAME,
      )
    } catch (error) {
      console.warn('Unable to fetch OAuth providers', error)
    }
  },

  loginWithAuthentik() {
    window.location.href = '/api/auth/oauth/authentik'
  },
}))
