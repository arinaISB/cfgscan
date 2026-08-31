// Package cli adapts command-line arguments and streams to the application.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"

	cfgscanv1 "cfgscan/api/gen/cfgscan/v1"
	"cfgscan/internal/analyzer"
	"cfgscan/internal/app"
	"cfgscan/internal/filescan"
	"cfgscan/internal/grpcapi"
	"cfgscan/internal/httpapi"
	"cfgscan/internal/input"

	"google.golang.org/grpc"
)

const usage = "usage: scanner [--http-addr <address> | --grpc-addr <address> | [-s|--silent] (--stdin | <config-file>)]"

type options struct {
	silent     bool
	stdin      bool
	path       string
	httpAddr   string
	httpServer bool
	grpcAddr   string
	grpcServer bool
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
	if opts.httpServer {
		if err := http.ListenAndServe(opts.httpAddr, httpapi.NewHandler(service)); err != nil {
			fmt.Fprintf(stderr, "serve HTTP API: %v\n", err)
			return 1
		}
		return 0
	}
	if opts.grpcServer {
		listener, err := net.Listen("tcp", opts.grpcAddr)
		if err != nil {
			fmt.Fprintf(stderr, "listen gRPC API: %v\n", err)
			return 1
		}
		grpcServer := grpc.NewServer()
		cfgscanv1.RegisterScannerServer(grpcServer, grpcapi.NewServer(service))
		if err := grpcServer.Serve(listener); err != nil {
			fmt.Fprintf(stderr, "serve gRPC API: %v\n", err)
			return 1
		}
		return 0
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
	flags.StringVar(&opts.httpAddr, "http-addr", "", "serve the HTTP API on this address")
	flags.StringVar(&opts.grpcAddr, "grpc-addr", "", "serve the gRPC API on this address")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}

	flags.Visit(func(f *flag.Flag) {
		if f.Name == "http-addr" {
			opts.httpServer = true
		}
		if f.Name == "grpc-addr" {
			opts.grpcServer = true
		}
	})
	remaining := flags.Args()
	if opts.httpServer && opts.grpcServer {
		return options{}, errors.New("--http-addr cannot be used with --grpc-addr")
	}
	if opts.httpServer {
		if opts.httpAddr == "" {
			return options{}, errors.New("--http-addr requires an address")
		}
		if opts.stdin || opts.silent || len(remaining) != 0 {
			return options{}, errors.New("--http-addr cannot be used with a configuration path, --stdin, -s, or --silent")
		}
		return opts, nil
	}
	if opts.grpcServer {
		if opts.grpcAddr == "" {
			return options{}, errors.New("--grpc-addr requires an address")
		}
		if opts.stdin || opts.silent || len(remaining) != 0 {
			return options{}, errors.New("--grpc-addr cannot be used with a configuration path, --stdin, -s, or --silent")
		}
		return opts, nil
	}
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
