package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
    health_grpc "example.com/health/grpc"
)

type Cfg struct {
	Address        string `gcfg:"address"`
	PrivKey        string `gcfg:"client-privkey"`
	Cert           string `gcfg:"client-cert"`
	CACert         string `gcfg:"client-cacert"`	
}

func main() {

	fmt.Println("Go gRPC Health Server starting!")

	health_check_port := 1234
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", health_check_port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}


	cfg := &Cfg{
		Cert: "tls.crt",
		PrivKey: "tls.key",
		CACert: "ca-bundle.crt",
	}
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.PrivKey)
	if err != nil {
		log.Fatalf("Health checking TLS key failed: %v", err)
		return
	}

	opts := []grpc.ServerOption{}
	// Enable TLS for all incoming connections.
	opts = append(opts, grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	grpcServer := grpc.NewServer(opts...)

	s := health_grpc.Server{}
	health_grpc.RegisterHealthServer(grpcServer, &s)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}

