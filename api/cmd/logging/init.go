package logging

import (
	"minecharts/cmd/config"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// Exported variables
var (
	Logger *logrus.Logger
	Auth   *AuthDomain
	Server *ServerDomain
	API    *APIDomain
	DB     *DBDomain
	K8s    *K8sDomain
)

// Field represents a log field with key and value
type Field struct {
	Key   string
	Value interface{}
}

// Init initializes the logger with the configured log level
func Init() {
	InitStructuredLogging()
	// Create new logger
	Logger = logrus.New()

	// Set output to stdout
	Logger.SetOutput(os.Stdout)

	// Set log format
	switch strings.ToLower(config.LogFormat) {
	case "text":
		Logger.SetFormatter(&logrus.TextFormatter{
			DisableColors:    false,
			DisableTimestamp: false,
			FullTimestamp:    true,
			TimestampFormat:  "2006/01/02 15:04:05",
		})
	case "json":
		Logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006/01/02 15:04:05",
		})
	default:
		Logger.SetFormatter(&logrus.TextFormatter{
			DisableColors:    false,
			DisableTimestamp: false,
			FullTimestamp:    true,
			TimestampFormat:  "2006/01/02 15:04:05",
		})
		Logger.Warnf("Invalid log format %s, using text format", config.LogFormat)
	}

	// Set log level from configuration
	level, err := logrus.ParseLevel(strings.ToLower(config.LogLevel))
	if err != nil {
		// Default to info level if parsing fails
		level = logrus.InfoLevel
		Logger.Warnf("Invalid log level %s, using info level", config.LogLevel)
	}
	Logger.SetLevel(level)

	Logger.Infof("Logger initialized with level: %s", level.String())
}

// WithFields returns a new entry with the specified fields
func WithFields(fields ...Field) *logrus.Entry {
	logrusFields := logrus.Fields{}
	for _, field := range fields {
		logrusFields[field.Key] = field.Value
	}
	return Logger.WithFields(logrusFields)
}

// Field creation helpers
func F(key string, value interface{}) Field {
	return Field{Key: key, Value: value}
}

// Initialization of domains
func InitStructuredLogging() {
	// Initialize Auth domain
	Auth = &AuthDomain{
		LogDomain: Domain("Auth"),
	}
	Auth.InvalidCredentials = Auth.LogDomain.Action("InvalidCredentials")
	Auth.SessionExpired = Auth.LogDomain.Action("SessionExpired")
	Auth.Session = Auth.LogDomain.Action("Session")

	// Initialize Login subdomain
	Auth.Login = &AuthLoginDomain{
		LogDomain: Auth.LogDomain.SubDomain("Login"),
	}

	// Initialize Register subdomain
	Auth.Register = &AuthRegisterDomain{
		LogDomain: Auth.LogDomain.SubDomain("Register"),
	}

	// Initialize JWT subdomain
	Auth.JWT = &AuthJWTDomain{
		LogDomain: Auth.LogDomain.SubDomain("JWT"),
	}

	// Initialize OAuth subdomain
	Auth.OAuth = &AuthOAuthDomain{
		LogDomain: Auth.LogDomain.SubDomain("OAuth"),
	}

	// Initialize Password subdomain
	Auth.Password = &AuthPasswordDomain{
		LogDomain: Auth.LogDomain.SubDomain("Password"),
	}

	// Initialize API domain
	API = &APIDomain{
		LogDomain: Domain("API"),
	}

	API.InvalidRequest = API.LogDomain.Action("InvalidRequest")
	API.Keys = API.LogDomain.Action("Keys")

	// Initialize Database domain
	DB = &DBDomain{
		LogDomain: Domain("Database"),
	}

	// Initialize K8s domain
	K8s = &K8sDomain{
		LogDomain: Domain("K8s"),
	}

	// Initialize Server domain
	Server = &ServerDomain{
		LogDomain: Domain("Server"),
	}
	Server.Started = Server.LogDomain.Action("Started")
	Server.Stopped = Server.LogDomain.Action("Stopped")
	Server.Restarted = Server.LogDomain.Action("Restarted")
	Server.Deleted = Server.LogDomain.Action("Deleted")
	Server.CommandExec = Server.LogDomain.Action("CommandExec")
}
