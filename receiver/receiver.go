package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	pb "logShipper/gRPC/logshipperpb"

	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedLogServiceServer
}

// Struct for Elasticsearch payload
type ESLog struct {
	EventID     string    `json:"event_id"`
	Timestamp   time.Time `json:"@timestamp"`
	Hostname    string    `json:"hostname"`
	User        string    `json:"user"`
	LogName     string    `json:"log_name"`
	Source      string    `json:"source"`
	Level       string    `json:"level"`
	Description string    `json:"description"`
	OrgID       string    `json:"org_id"`
	Tags        []string  `json:"tags"`
	AgentIP     string    `json:"agent_ip"`
	AgentUser   string    `json:"agent_user"`
}

func (s *server) SendLog(ctx context.Context, req *pb.LogRequest) (*pb.LogResponse, error) {
	fmt.Println("📩 Incoming gRPC request...")
	log.Printf("✅ Received log from %s | Event ID: %s | Description: %s\n", req.Hostname, req.EventId, req.Description)

	// Map gRPC log to Elasticsearch format
	esLog := ESLog{
		EventID:     req.EventId,
		Timestamp:   time.Now(), // Or parse req.Timestamp if you send actual time
		Hostname:    req.Hostname,
		User:        req.User,
		LogName:     req.LogName,
		Source:      req.Source,
		Level:       req.Level,
		Description: req.Description,
		OrgID:       req.OrgId,
		Tags:        req.Tags,
		AgentIP:     req.AgentIp,
		// AgentUser:   req.AgentUser,
	}

	jsonData, err := json.Marshal(esLog)
	if err != nil {
		log.Printf("❌ Failed to marshal log: %v", err)
		return &pb.LogResponse{Status: "error"}, err
	}

	// Send to Elasticsearch
	esURL := "http://localhost:9200/logs/_doc"
	resp, err := http.Post(esURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("❌ Error sending to Elasticsearch: %v", err)
		return &pb.LogResponse{Status: "error"}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		log.Printf("⚠️ Elasticsearch returned status: %s", resp.Status)
	} else {
		log.Printf("📤 Sent to Elasticsearch successfully")
	}

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
