package main

import (
    "fmt"
    "log"

    "golang.org/x/net/context"
    "google.golang.org/grpc"

    health_grpc "example.com/health/grpc"
)

func main() {

    var conn *grpc.ClientConn
    health_check_ip := ""
    health_check_port := 1234
    node_addr := fmt.Sprintf("%s:%d", health_check_ip, health_check_port)
    conn, err := grpc.Dial(node_addr, grpc.WithInsecure())
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

