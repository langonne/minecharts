import Alpine from 'alpinejs'

type OAuthProvidersPayload = {
  providers?: Array<{ name: string; display_name?: string; login_url?: string }>
}

type OAuthProvider = {
  name: string
  displayName: string
  loginUrl: string
}

Alpine.data('loginForm', () => ({
  hasError: false,
  errorMessage: '',
  oauthProviders: [] as OAuthProvider[],

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
      this.oauthProviders = providers
        .filter((provider) => Boolean(provider?.name))
        .map((provider) => ({
          name: provider.name,
          displayName: provider.display_name || provider.name,
          loginUrl: provider.login_url || `/api/auth/oauth/${provider.name}`,
        }))
    } catch (error) {
      console.warn('Unable to fetch OAuth providers', error)
    }
  },

  loginWithProvider(provider?: OAuthProvider) {
    const selected = provider ?? this.oauthProviders[0]
    if (!selected) return
    window.location.href = selected.loginUrl
  },
}))
