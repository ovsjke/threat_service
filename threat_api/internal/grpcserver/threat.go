
package grpcserver

import (
    "context"
    "errors"

    "github.com/ovsjke/threat_service/threat_api/internal/entity"

    threatv1 "github.com/ovsjke/threat_service/contracts/gen/go/threat/v1"

    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
    "google.golang.org/protobuf/types/known/timestamppb"
)

type ThreatService interface {
    GetByMD5(ctx context.Context, md5 string) (*entity.Threat, error)
    Create(ctx context.Context, threat *entity.Threat) (*entity.Threat, error)
}

type Server struct {
    threatv1.UnimplementedThreatServiceServer

    service ThreatService
}

func New(service ThreatService) *Server {
    return &Server{
        service: service,
    }
}

func (s *Server) GetThreat(
    ctx context.Context,
    req *threatv1.GetThreatRequest,
) (*threatv1.Threat, error) {
    threat, err := s.service.GetByMD5(ctx, req.GetMd5())
    if err != nil {
        return nil, toGRPCError(err)
    }

    return toProto(threat), nil
}

func (s *Server) CreateThreat(
    ctx context.Context,
    req *threatv1.CreateThreatRequest,
) (*threatv1.Threat, error) {
    if req == nil {
        return nil, status.Error(
            codes.InvalidArgument,
            "request must not be empty",
        )
    }

    threat, err := s.service.Create(ctx, &entity.Threat{
        MD5:         req.GetMd5(),
        Name:        req.GetName(),
        Description: req.GetDescription(),
        Severity:    entity.Severity(req.GetSeverity()),
    })
    if err != nil {
        return nil, toGRPCError(err)
    }

    return toProto(threat), nil
}


func toProto(threat *entity.Threat) *threatv1.Threat {
    return &threatv1.Threat{
        Md5:         threat.MD5,
        Name:        threat.Name,
        Description: threat.Description,
        Severity:    string(threat.Severity),
        DetectedAt:  timestamppb.New(threat.DetectedAt),
        UpdatedAt:   timestamppb.New(threat.UpdatedAt),
    }
}

func toGRPCError(err error) error {
    switch {
    case errors.Is(err, context.Canceled):
        return status.Error(codes.Canceled, "request canceled")

    case errors.Is(err, context.DeadlineExceeded):
        return status.Error(codes.DeadlineExceeded, "deadline exceeded")

    case errors.Is(err, entity.ErrThreatNotFound):
        return status.Error(codes.NotFound, "threat not found")
    case errors.Is(err, entity.ErrThreatNotFound):
        return status.Error(codes.NotFound, "threat not found")

    case errors.Is(err, entity.ErrThreatAlreadyExists):
        return status.Error(codes.AlreadyExists, "threat already exists")

    case errors.Is(err, entity.ErrInvalidMD5):
        return status.Error(codes.InvalidArgument, "invalid MD5")

    case errors.Is(err, entity.ErrInvalidName):
        return status.Error(codes.InvalidArgument, "invalid name")

    case errors.Is(err, entity.ErrNameTooLong):
        return status.Error(codes.InvalidArgument, "name is too long")

    case errors.Is(err, entity.ErrInvalidSeverity):
        return status.Error(codes.InvalidArgument, "invalid severity")

    default:
        return status.Error(codes.Internal, "internal server error")
    }
}
