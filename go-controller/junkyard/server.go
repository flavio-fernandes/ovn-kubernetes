package main

import (
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
    health_grpc "example.com/health/grpc"
)

func main() {

	fmt.Println("Go gRPC Health Server starting!")

	health_check_port := 1234
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", health_check_port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := health_grpc.Server{}
	grpcServer := grpc.NewServer()

	health_grpc.RegisterHealthServer(grpcServer, &s)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}

