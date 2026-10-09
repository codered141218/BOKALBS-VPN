//go:build !windows

package config

// On other systems the settings file is only readable by its owner (0600).
func protect(data []byte) ([]byte, error)   { return data, nil }
func unprotect(data []byte) ([]byte, error) { return data, nil }
