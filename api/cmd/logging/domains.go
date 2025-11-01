package logging

// Typed structures for domains
type AuthDomain struct {
	*LogDomain
	// Direct actions
	InvalidCredentials *LogAction
	SessionExpired     *LogAction
	Session            *LogAction

	// Sub-domains
	Login    *AuthLoginDomain
	Register *AuthRegisterDomain
	JWT      *AuthJWTDomain
	OAuth    *AuthOAuthDomain
	Password *AuthPasswordDomain
}

type ServerDomain struct {
	*LogDomain
	Started     *LogAction
	Stopped     *LogAction
	Restarted   *LogAction
	Deleted     *LogAction
	CommandExec *LogAction
}

type APIDomain struct {
	*LogDomain
	InvalidRequest *LogAction
	Keys           *LogAction
}

type DBDomain struct {
	*LogDomain
}

type K8sDomain struct {
	*LogDomain
}

// Sub-domain structures

type AuthLoginDomain struct {
	*LogDomain
}

type AuthRegisterDomain struct {
	*LogDomain
}

type AuthJWTDomain struct {
	*LogDomain
}

type AuthOAuthDomain struct {
	*LogDomain
}

type AuthPasswordDomain struct {
	*LogDomain
}
