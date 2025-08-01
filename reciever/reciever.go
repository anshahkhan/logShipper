package main

import (
	"context"
	"fmt"
	"log"
	pb "logShipper/gRPC/logshipperpb"
	"net"

	"google.golang.org/grpc"
)

// ✅ Must match your go.mod module name exactly

// server implements the gRPC LogReceiverServer interface
type server struct {
	pb.UnimplementedLogServiceServer
}

// ReceiveLog handles incoming logs from agents
func (s *server) SendLog(ctx context.Context, req *pb.LogRequest) (*pb.LogResponse, error) {
	fmt.Println("📩 Incoming gRPC request...")
	log.Printf("✅ Received log from %s | Event ID: %s | Description: %s\n", req.Hostname, req.EventId, req.Description)
	return &pb.LogResponse{Status: "received"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("❌ Failed to listen: %v", err)
	}
	log.Println("🚀 gRPC server listening on :50051")

	grpcServer := grpc.NewServer()
	pb.RegisterLogServiceServer(grpcServer, &server{})

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("❌ Failed to serve gRPC: %v", err)
	}
}
