package main

import (
	"context"
	"log"
	"net"

	pb "github.com/anshahkhan/logShipper/gRPC/logshipperpb" // ✅ Must match your go.mod module name exactly
	"google.golang.org/grpc"
)

// server implements the gRPC LogReceiverServer interface
type server struct {
	pb.UnimplementedLogReceiverServer
}

// ReceiveLog handles incoming logs from agents
func (s *server) ReceiveLog(ctx context.Context, req *pb.LogRequest) (*pb.LogResponse, error) {
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
	pb.RegisterLogReceiverServer(grpcServer, &server{})

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("❌ Failed to serve gRPC: %v", err)
	}
}
