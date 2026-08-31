// Package cli adapts command-line arguments and streams to the application.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"cfgscan/internal/analyzer"
	"cfgscan/internal/app"
	"cfgscan/internal/filescan"
	"cfgscan/internal/input"
)

const usage = "usage: scanner [-s|--silent] [--stdin] <config-file>"

type options struct {
	silent bool
	stdin  bool
	path   string
}

type openFileFunc func(string) (input.Source, io.Closer, error)

// Run executes the command-line application and returns its process exit code.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, service app.Service, openFile openFileFunc) int {
	opts, err := parse(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprintln(stderr, usage)
		return 2
	}

	if opts.stdin {
		problems, err := service.Analyze(ctx, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "analyze stdin: %v\n", err)
			return 1
		}
		return writeProblems(stdout, problems, "stdin", opts.silent)
	}

	paths, err := filescan.Files(opts.path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	allProblems := make([]analyzer.Problem, 0)
	for _, path := range paths {
		source, closeSource, err := openFile(path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		problems, analyzeErr := service.Analyze(ctx, source.Reader)
		closeErr := closeSource.Close()
		if analyzeErr != nil {
			fmt.Fprintf(stderr, "analyze %s: %v\n", path, analyzeErr)
			return 1
		}
		if closeErr != nil {
			fmt.Fprintf(stderr, "close configuration file %q: %v\n", path, closeErr)
			return 1
		}
		for index := range problems {
			problems[index].Source = path
		}
		allProblems = append(allProblems, problems...)
		permission, permissionErr := filescan.PermissionProblem(path)
		if permissionErr != nil {
			fmt.Fprintln(stderr, permissionErr)
			return 1
		}
		if permission != nil {
			allProblems = append(allProblems, *permission)
		}
	}
	return writeProblems(stdout, allProblems, "", opts.silent)
}

func writeProblems(stdout io.Writer, problems []analyzer.Problem, defaultSource string, silent bool) int {
	for _, problem := range problems {
		source := problem.Source
		if source == "" {
			source = defaultSource
		}
		fmt.Fprintf(stdout, "%s: %s [%s] %s: %s Recommendation: %s\n", source, problem.Severity, problem.RuleID, problem.Path, problem.Message, problem.Recommendation)
	}
	if len(problems) > 0 && !silent {
		return 1
	}
	return 0
}

func parse(args []string) (options, error) {
	var opts options
	flags := flag.NewFlagSet("scanner", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&opts.silent, "s", false, "suppress a non-zero exit code for findings")
	flags.BoolVar(&opts.silent, "silent", false, "suppress a non-zero exit code for findings")
	flags.BoolVar(&opts.stdin, "stdin", false, "read configuration from standard input")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}

	remaining := flags.Args()
	if opts.stdin {
		if len(remaining) != 0 {
			return options{}, errors.New("a configuration path cannot be used with --stdin")
		}
		return opts, nil
	}
	if len(remaining) == 0 {
		return options{}, errors.New("configuration file path is required unless --stdin is used")
	}
	if len(remaining) > 1 {
		return options{}, errors.New("only one configuration file path is allowed")
	}
	opts.path = remaining[0]
	return opts, nil
}
