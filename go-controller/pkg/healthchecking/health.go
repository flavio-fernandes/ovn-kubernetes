package healthchecking

import (
	"golang.org/x/net/context"
)

const (
	ServiceEgressIpNode = "Service_Egress_IP"
)

// UnimplementedHealthServer must be embedded to have forward compatible implementations.
type Server struct {
	UnimplementedHealthServer
}

func (Server) Check(_ context.Context, req *HealthCheckRequest) (*HealthCheckResponse, error) {
	response := HealthCheckResponse{}
	if req.GetService() == ServiceEgressIpNode {
		response.Status = HealthCheckResponse_SERVING
	} else {
		response.Status = HealthCheckResponse_NOT_SERVING
	}
	return &response, nil
}
