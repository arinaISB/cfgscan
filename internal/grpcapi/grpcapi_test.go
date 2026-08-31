package grpcapi

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	cfgscanv1 "cfgscan/api/gen/cfgscan/v1"
	"cfgscan/internal/analyzer"
	"cfgscan/internal/app"
	"cfgscan/internal/parser"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name    string
		service app.Service
		input   string
		code    codes.Code
		check   func(*testing.T, *cfgscanv1.AnalyzeResponse)
	}{
		{
			name: "safe JSON", service: app.New(analyzer.NewEngine(analyzer.DefaultRules()...)),
			input: `{"service":{"port":8080}}`, code: codes.OK,
			check: func(t *testing.T, response *cfgscanv1.AnalyzeResponse) {
				if len(response.GetProblems()) != 0 {
					t.Fatalf("problems = %#v, want none", response.GetProblems())
				}
			},
		},
		{
			name: "YAML finding", service: app.New(analyzer.NewEngine(analyzer.DefaultRules()...)),
			input: "database:\n  password: literal-password\n", code: codes.OK,
			check: func(t *testing.T, response *cfgscanv1.AnalyzeResponse) {
				if len(response.GetProblems()) != 1 {
					t.Fatalf("problems = %#v, want one", response.GetProblems())
				}
				problem := response.GetProblems()[0]
				if problem.GetRuleId() != "plaintext-password" || problem.GetSeverity() != "HIGH" || problem.GetPath() != "database.password" || problem.GetSource() != "request" {
					t.Fatalf("problem = %#v", problem)
				}
			},
		},
		{name: "empty input", service: app.New(analyzer.NewEngine()), input: " \n", code: codes.InvalidArgument},
		{name: "invalid input", service: app.New(analyzer.NewEngine()), input: "{invalid", code: codes.InvalidArgument},
		{
			name: "payload too large", service: app.New(analyzer.NewEngine()),
			input: strings.Repeat("a", maxConfigurationBytes+1), code: codes.ResourceExhausted,
		},
		{name: "analyzer error", service: app.New(errorAnalyzer{}), input: "valid: true\n", code: codes.Internal},
	}

	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				client, cleanup := newClient(t, test.service)
				defer cleanup()
				response, err := client.Analyze(
					context.Background(), &cfgscanv1.AnalyzeRequest{Configuration: test.input},
				)
				if status.Code(err) != test.code {
					t.Fatalf("status code = %v, want %v (error = %v)", status.Code(err), test.code, err)
				}
				if test.code == codes.OK {
					test.check(t, response)
				}
			},
		)
	}
}

func newClient(t *testing.T, service app.Service) (cfgscanv1.ScannerClient, func()) {
	t.Helper()
	listener := bufconn.Listen(bufSize)
	server := grpc.NewServer()
	cfgscanv1.RegisterScannerServer(server, NewServer(service))
	go func() { _ = server.Serve(listener) }()
	connection, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(
			func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			},
		),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	return cfgscanv1.NewScannerClient(connection), func() {
		_ = connection.Close()
		server.Stop()
		_ = listener.Close()
	}
}

type errorAnalyzer struct{}

func (errorAnalyzer) Analyze(context.Context, parser.Document) ([]analyzer.Problem, error) {
	return nil, errors.New("analysis failed")
}
