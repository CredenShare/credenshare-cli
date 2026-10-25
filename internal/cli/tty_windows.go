//go:build windows

package cli

import "os"

// openTTY opens the console, which stays the console when stdin is a pipe.
func openTTY() (in, out *os.File, closeTTY func(), err error) {
	in, err = os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	out, err = os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		_ = in.Close()
		return nil, nil, nil, err
	}
	return in, out, func() { _ = in.Close(); _ = out.Close() }, nil
}
