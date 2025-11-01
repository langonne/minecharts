import Alpine from 'alpinejs'

Alpine.data('loginForm', () => ({
  hasError: false,
  errorMessage: '',

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
}))
