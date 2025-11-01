type FeedbackForm = {
    type: 'bug' | 'feature' | 'other'
    title: string
    description: string
}

type FeedbackSuccess = {
    issue_url?: string
    issue_number?: number
}

const defaultForm = (): FeedbackForm => ({
    type: 'bug',
    title: '',
    description: '',
})

export function feedbackModal() {
    return {
        open: false,
        sending: false,
        error: '',
        success: null as FeedbackSuccess | null,
        form: defaultForm(),
        close() {
            this.open = false
            if (this.success) {
                this.reset()
            }
        },
        reset() {
            this.error = ''
            this.success = null
            this.sending = false
            this.form = defaultForm()
        },
        async submit() {
            if (this.sending || this.success) {
                return
            }

            const title = this.form.title.trim()
            const description = this.form.description.trim()

            if (!title || !description) {
                this.error = 'Titre et description sont obligatoires'
                return
            }

            this.sending = true
            this.error = ''

            try {
                const response = await fetch('/api/feedback', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        type: this.form.type,
                        title,
                        description,
                    }),
                })

                if (response.status === 401) {
                    this.error = 'Session expirée. Veuillez vous reconnecter.'
                    return
                }

                if (!response.ok) {
                    let message = "Impossible d'envoyer le feedback"
                    try {
                        const data = await response.json()
                        if (data?.error) {
                            message = data.error
                        }
                    } catch {
                        // ignore JSON parse errors and keep generic message
                    }
                    this.error = message
                    return
                }

                const data: FeedbackSuccess = await response.json()
                this.success = data
            } catch {
                this.error = 'Erreur réseau. Réessaie plus tard.'
            } finally {
                this.sending = false
            }
        },
    }
}

declare global {
    interface Window {
        feedbackModal: typeof feedbackModal
    }
}

window.feedbackModal = feedbackModal
