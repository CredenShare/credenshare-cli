// Command credenshare creates and manages CredenShare shares and secure requests from a
// terminal. Content is encrypted on this machine before anything is sent.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/CredenShare/credenshare-cli/internal/cli"
)

func main() {
	// Ctrl+C cancels the context rather than killing the process outright, so a request in
	// flight is abandoned cleanly and a hidden prompt gets to turn echo back on.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.NewApp().Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
