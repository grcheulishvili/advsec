//go:build !linux

package engine

// traceUpstreamCommand is a no-op on non-Linux platforms: automatic /proc pipe
// tracing is Linux-specific, so callers transparently fall back to $ADVSEC_CMD
// or the --cmd flag.
func traceUpstreamCommand() string { return "" }
