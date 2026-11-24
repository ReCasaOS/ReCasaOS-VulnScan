package service

import "golang.org/x/sys/unix"

// FreeBytes is the room left in dir for a process that is not root's reserve.
func FreeBytes(dir string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(dir, &stat); err != nil {
		return 0, err
	}

	return stat.Bavail * uint64(stat.Bsize), nil
}
