package grpc

import (
        "fmt"
        "golang.org/x/net/context"
		codes "google.golang.org/grpc/codes"
		status "google.golang.org/grpc/status"
	)

const (
	ServiceEgressIpNode = "Service_Egress_IP"
)
	

// UnimplementedHealthServer must be embedded to have forward compatible implementations.
type Server struct {
}

func (Server) Check(c context.Context, req *HealthCheckRequest) (*HealthCheckResponse, error) {
	response := HealthCheckResponse{}
	if req.GetService() == ServiceEgressIpNode {
		response.Status = HealthCheckResponse_SERVING
	} else {
		response.Status = HealthCheckResponse_NOT_SERVING
	}
	fmt.Println("now responding:", response.GetStatus())
    return &response, nil
}

func (Server) Watch(*HealthCheckRequest, Health_WatchServer) error {
	return status.Errorf(codes.Unimplemented, "method Watch not implemented")
}

func (Server) mustEmbedUnimplementedHealthServer() {}

