package version

// Populated at build time via -ldflags; defaults cover local dev builds.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)
