//go:build !windows

package tunnel

// AllowProgram is only needed on Windows.
func AllowProgram() error { return nil }
