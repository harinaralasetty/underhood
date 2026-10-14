// Underhood is an offline, deterministic app inspector.
package main

import (
	"github.com/harinaralasetty/underhood/internal/cli"
	"os"
)

func main() { os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr)) }
