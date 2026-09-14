//go:build windows

package main

// Windows is used for development tests; production is the Linux build, whose
// implementation fsyncs the directory after every atomic replacement.
func syncDirectory(string) error { return nil }
