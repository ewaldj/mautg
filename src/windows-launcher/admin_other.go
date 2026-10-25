//go:build !windows

package main

func isElevated() bool                    { return false }
func relaunchElevated(args []string) bool { return false }
func ensureFirewall(python string)        {}
