//go:build !windows

package cli

import "os"

// openTTY opens the controlling terminal, which stays a terminal when stdin is a pipe.
func openTTY() (in, out *os.File, closeTTY func(), err error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	return tty, tty, func() { _ = tty.Close() }, nil
}
