import Alpine from 'alpinejs'

Alpine.data('loginForm', () => ({
  hasError: false,
  errorMessage: '',
  authentikLoginEnabled: import.meta.env.VITE_AUTHENTIK_LOGIN_ENABLED === 'true',

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
  },

  loginWithAuthentik() {
    window.location.href = '/api/auth/oauth/authentik'
  },
}))
