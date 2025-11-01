package logging

import (
	"fmt"
)

// LogDomain represents a functional domain for logging
type LogDomain struct {
	name   string
	fields []Field
}

// LogAction represents a specific action within a domain
type LogAction struct {
	domain *LogDomain
	action string
}

// LogMessage is a function that constructs and emits a log message
type LogMessage func(args ...interface{})

// Domain creates a new logging domain
func Domain(name string) *LogDomain {
	return &LogDomain{
		name:   name,
		fields: []Field{F("domain", name)},
	}
}

// WithField adds a default field to the domain
func (d *LogDomain) WithField(key string, value interface{}) *LogDomain {
	d.fields = append(d.fields, F(key, value))
	return d
}

// Action defines an action within a domain
func (d *LogDomain) Action(name string) *LogAction {
	return &LogAction{
		domain: d,
		action: name,
	}
}

// Debug creates a Debug level logger for this domain
func (d *LogDomain) Debug(msg string, args ...interface{}) {
	entry := WithFields(d.fields...)
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	entry.Debug(msg)
}

// Info creates an Info level logger for this domain
func (d *LogDomain) Info(msg string, args ...interface{}) {
	entry := WithFields(d.fields...)
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	entry.Info(msg)
}

// Warn creates a Warning level logger for this domain
func (d *LogDomain) Warn(msg string, args ...interface{}) {
	entry := WithFields(d.fields...)
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	entry.Warn(msg)
}

// Error creates an Error level logger for this domain
func (d *LogDomain) Error(msg string, args ...interface{}) {
	entry := WithFields(d.fields...)
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	entry.Error(msg)
}

// Add relevant methods for LogAction (Debug, Info, Warn, Error)
func (a *LogAction) Debug(args ...interface{}) {
	fields := append(a.domain.fields, F("action", a.action))
	entry := WithFields(fields...)
	entry.Debug(a.getMessage(args...))
}

func (a *LogAction) Info(args ...interface{}) {
	fields := append(a.domain.fields, F("action", a.action))
	entry := WithFields(fields...)
	entry.Info(a.getMessage(args...))
}

func (a *LogAction) Warn(args ...interface{}) {
	fields := append(a.domain.fields, F("action", a.action))
	entry := WithFields(fields...)
	entry.Warn(a.getMessage(args...))
}

func (a *LogAction) Error(args ...interface{}) {
	fields := append(a.domain.fields, F("action", a.action))
	entry := WithFields(fields...)
	entry.Error(a.getMessage(args...))
}

// getMessage constructs the message based on the provided arguments
func (a *LogAction) getMessage(args ...interface{}) string {
	if len(args) == 0 {
		return fmt.Sprintf("%s %s", a.domain.name, a.action)
	}

	// If the first argument is an error, special handling
	if err, ok := args[0].(error); ok && len(args) == 1 {
		return fmt.Sprintf("%s %s: %v", a.domain.name, a.action, err)
	}

	// If the first argument is a string and there is an error as the second argument
	if msg, ok := args[0].(string); ok && len(args) > 1 {
		if err, ok := args[1].(error); ok {
			return fmt.Sprintf("%s %s: %s - %v", a.domain.name, a.action, msg, err)
		}
		return fmt.Sprintf("%s %s: %s", a.domain.name, a.action, msg)
	}

	// Default case
	return fmt.Sprintf("%s %s: %v", a.domain.name, a.action, args)
}

// SubDomain allows creating a subdomain
func (d *LogDomain) SubDomain(name string) *LogDomain {
	return &LogDomain{
		name:   d.name + "." + name,
		fields: append(d.fields, F("subdomain", name)),
	}
}

// WithError adds an error to the fields of a LogAction
func (a *LogAction) WithError(err error) *LogAction {
	if err != nil {
		a.domain.fields = append(a.domain.fields, F("error", err.Error()))
	}
	return a
}

// WithFields adds multiple fields without modifying the global instance
func (a *LogAction) WithFields(keyvals ...interface{}) *LogAction {
	// Check for pairs
	if len(keyvals)%2 != 0 {
		Logger.Warn("WithFields called with odd number of arguments")
		return a
	}

	// Create a copy of LogAction to avoid modifying the original
	newAction := &LogAction{
		domain: &LogDomain{
			name:   a.domain.name,
			fields: make([]Field, len(a.domain.fields)),
		},
		action: a.action,
	}

	// Copy the existing fields
	copy(newAction.domain.fields, a.domain.fields)

	// Add all new fields
	for i := 0; i < len(keyvals); i += 2 {
		key, ok := keyvals[i].(string)
		if !ok {
			Logger.Warnf("WithFields: non-string key %v ignored", keyvals[i])
			continue
		}
		newAction.domain.fields = append(newAction.domain.fields, F(key, keyvals[i+1]))
	}

	return newAction
}

// WithFields adds multiple fields to a domain in a single call
func (d *LogDomain) WithFields(keyvals ...interface{}) *LogDomain {
	// Check for pairs
	if len(keyvals)%2 != 0 {
		Logger.Warn("WithFields called with odd number of arguments")
		return d
	}

	// Create a copy to avoid modifying the original domain
	newDomain := &LogDomain{
		name:   d.name,
		fields: make([]Field, len(d.fields)),
	}
	copy(newDomain.fields, d.fields)

	// Add all new fields
	for i := 0; i < len(keyvals); i += 2 {
		key, ok := keyvals[i].(string)
		if !ok {
			Logger.Warnf("WithFields: non-string key %v ignored", keyvals[i])
			continue
		}
		newDomain.fields = append(newDomain.fields, F(key, keyvals[i+1]))
	}

	return newDomain
}
