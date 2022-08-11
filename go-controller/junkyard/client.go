package main

import (
    "fmt"
    "log"

    "golang.org/x/net/context"
    "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

    health_grpc "example.com/health/grpc"
)

type Cfg struct {
	Address        string `gcfg:"address"`
	PrivKey        string `gcfg:"client-privkey"`
	Cert           string `gcfg:"client-cert"`
	CACert         string `gcfg:"client-cacert"`	
	CertCommonName string `gcfg:"cert-common-name"`
}

func main() {

    var conn *grpc.ClientConn
    health_check_ip := ""
    health_check_port := 1234
    node_addr := fmt.Sprintf("%s:%d", health_check_ip, health_check_port)

    cfg := &Cfg{
		Cert: "tls.crt",
		PrivKey: "tls.key",
		CACert: "ca-bundle.crt",
        CertCommonName: "ovn",
	}

    // Set up the credentials for the connection.
    creds, err := credentials.NewClientTLSFromFile(cfg.CACert, cfg.CertCommonName)
    if err != nil {
        log.Fatalf("failed to load credentials: %v", err)
    }
    opts := []grpc.DialOption{
        grpc.WithTransportCredentials(creds),
    }
    conn, err = grpc.Dial(node_addr, opts...)
    if err != nil {
        log.Fatalf("did not connect: %s", err)
    }
    defer conn.Close()

    c := health_grpc.NewHealthClient(conn)

    response, err := c.Check(context.Background(), &health_grpc.HealthCheckRequest{Service: health_grpc.ServiceEgressIpNode})
    if err != nil {
        log.Fatalf("Error when calling Check: %s", err)
    }
    log.Printf("Response from server: %v", response.GetStatus())

}

