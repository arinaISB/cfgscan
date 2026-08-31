// Package grpcapi exposes configuration analysis over gRPC.
package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"strings"

	cfgscanv1 "cfgscan/api/gen/cfgscan/v1"
	"cfgscan/internal/app"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maxConfigurationBytes = 1 << 20

// Server implements the cfgscan Scanner gRPC service.
type Server struct {
	cfgscanv1.UnimplementedScannerServer
	service app.Service
}

// NewServer returns a Scanner server backed by service.
func NewServer(service app.Service) *Server {
	return &Server{service: service}
}

// Analyze analyzes one raw JSON or YAML configuration document.
func (s *Server) Analyze(ctx context.Context, request *cfgscanv1.AnalyzeRequest) (*cfgscanv1.AnalyzeResponse, error) {
	configuration := request.GetConfiguration()
	if len(configuration) > maxConfigurationBytes {
		return nil, status.Error(codes.ResourceExhausted, "configuration exceeds 1 MiB")
	}
	if strings.TrimSpace(configuration) == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is empty")
	}

	problems, err := s.service.Analyze(ctx, bytes.NewBufferString(configuration))
	if err != nil {
		var parseErr *app.ParseError
		if errors.As(err, &parseErr) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Internal, "analyze configuration")
	}

	response := &cfgscanv1.AnalyzeResponse{Problems: make([]*cfgscanv1.Problem, 0, len(problems))}
	for _, problem := range problems {
		response.Problems = append(response.Problems, &cfgscanv1.Problem{
			Source:         "request",
			RuleId:         problem.RuleID,
			Severity:       string(problem.Severity),
			Path:           problem.Path,
			Message:        problem.Message,
			Recommendation: problem.Recommendation,
		})
	}
	return response, nil
}
