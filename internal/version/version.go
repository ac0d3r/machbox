package version

// Version is the machbox release version. Host and guest-agent are built
// together and share this value (injected via -X at build time).
var Version = "dev"
