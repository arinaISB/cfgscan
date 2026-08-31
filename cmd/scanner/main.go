package main

import (
	"context"
	"os"

	"cfgscan/internal/analyzer"
	"cfgscan/internal/app"
	"cfgscan/internal/cli"
	"cfgscan/internal/input"
)

func main() {
	exitCode := cli.Run(
		context.Background(),
		os.Args[1:],
		os.Stdin,
		os.Stdout,
		os.Stderr,
		app.New(analyzer.NewEngine(analyzer.DefaultRules()...)),
		input.OpenFile,
	)
	os.Exit(exitCode)
}
