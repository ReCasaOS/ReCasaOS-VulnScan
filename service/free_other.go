//go:build !linux

package service

import "errors"

// FreeBytes is only told on Linux, where the service runs; elsewhere the room is unknown
// and the scanner scans without asking.
func FreeBytes(string) (uint64, error) {
	return 0, errors.New("the room left is not read on this system")
}
