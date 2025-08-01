package main

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"net"
	"os"
	"os/exec"

	// "os/user"
	"regexp"
	"strings"
	"time"

	pb "logShipper/gRPC/logshipperpb"
	"logShipper/internal"

	"google.golang.org/grpc"
)

func shouldInclude(eventID string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := regexp.MatchString(pattern, eventID)
		if err != nil {
			log.Printf("❌ Invalid regex pattern: %s", pattern)
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

func parseLog(output string) map[string]interface{} {
	clean := func(s string) string {
		s = strings.ReplaceAll(s, "\u0000", "")
		return strings.TrimSpace(s)
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	logData := make(map[string]interface{})
	var descriptionBuffer bytes.Buffer
	var inDescription bool

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "  Log Name:"):
			logData["log_name"] = clean(strings.TrimPrefix(line, "  Log Name:"))
		case strings.HasPrefix(line, "  Source:"):
			logData["source"] = clean(strings.TrimPrefix(line, "  Source:"))
		case strings.HasPrefix(line, "  Date:"):
			logData["timestamp"] = clean(strings.TrimPrefix(line, "  Date:"))
		case strings.HasPrefix(line, "  Event ID:"):
			logData["event_id"] = clean(strings.TrimPrefix(line, "  Event ID:"))
		case strings.HasPrefix(line, "  Level:"):
			logData["level"] = clean(strings.TrimPrefix(line, "  Level:"))
		case strings.HasPrefix(line, "  User Name:"):
			logData["user"] = clean(strings.TrimPrefix(line, "  User Name:"))
		case strings.HasPrefix(line, "  Description:"):
			inDescription = true
		case inDescription:
			if strings.TrimSpace(line) == "" {
				inDescription = false
			} else {
				descriptionBuffer.WriteString(line + "\n")
			}
		}
	}

	if descriptionBuffer.Len() > 0 {
		logData["description"] = clean(descriptionBuffer.String())
	}

	return logData
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
	}
	return "unknown"
}

func getTags(logType, eventID, description string) []string {
	tags := []string{"windows", "agent"}

	if strings.Contains(logType, "Sysmon") {
		tags = append(tags, "sysmon")
	}
	if strings.Contains(logType, "Security") {
		tags = append(tags, "security")
	}
	if strings.Contains(logType, "PowerShell") {
		tags = append(tags, "powershell")
	}
	if strings.Contains(logType, "Rdp") || strings.Contains(description, "Remote Desktop") {
		tags = append(tags, "rdp")
	}
	if strings.Contains(logType, "WinINet") || strings.Contains(description, "proxy") {
		tags = append(tags, "network", "proxy")
	}
	if strings.Contains(logType, "RasClient") || strings.Contains(description, "VPN") {
		tags = append(tags, "vpn")
	}

	switch eventID {
	case "4624":
		tags = append(tags, "auth", "logon")
	case "4625":
		tags = append(tags, "auth", "failed_logon")
	case "1102":
		tags = append(tags, "log_clear")
	case "4688":
		tags = append(tags, "process", "exec")
	case "1116":
		tags = append(tags, "malware")
	case "20227", "20225", "20269":
		tags = append(tags, "vpn")
	}

	return tags
}

func main() {
	cfg, err := internal.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("❌ Error loading config: %v", err)
	}

	conn, err := grpc.Dial(cfg.ServerIP+":"+cfg.Port, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("❌ Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := pb.NewLogServiceClient(conn)

	hostname, _ := os.Hostname()
	// agentUser, _ := user.Current()
	localIP := getLocalIP()

	for {
		for _, logType := range cfg.LogTypes {
			log.Printf("🔍 Checking logs for: %s", logType)

			cmd := exec.Command("wevtutil", "qe", logType, "/c:30", "/f:text")
			out, err := cmd.Output()
			if err != nil {
				log.Printf("[%s] Error fetching logs: %v", logType, err)
				continue
			}

			events := strings.Split(string(out), "Event[")
			for _, raw := range events {
				if strings.TrimSpace(raw) == "" {
					continue
				}

				raw = "Event[" + raw
				logEntry := parseLog(raw)
				if logEntry == nil {
					continue
				}

				eventID, ok := logEntry["event_id"].(string)
				if !ok {
					log.Printf("[%s] Missing Event ID: %+v", logType, logEntry)
					continue
				}

				log.Printf("[%s] Seen Event ID: %s", logType, eventID)

				if !shouldInclude(eventID, cfg.EventPatterns) {
					continue
				}

				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)

				resp, err := client.SendLog(ctx, &pb.LogRequest{
					OrgId:       cfg.OrgID,
					AgentIp:     localIP,
					Hostname:    hostname,
					EventId:     eventID,
					LogName:     logEntry["log_name"].(string),
					Source:      logEntry["source"].(string),
					Level:       logEntry["level"].(string),
					User:        logEntry["user"].(string),
					Description: logEntry["description"].(string),
					Timestamp:   logEntry["timestamp"].(string),
					Tags:        getTags(logType, eventID, logEntry["description"].(string)),
				})
				cancel()
				if err != nil {
					log.Printf("[%s] ❌ gRPC send error: %v", logType, err)
				} else {
					log.Printf("[%s] ✅ gRPC server response: %s", logType, resp.Status)
				}
			}
		}

		log.Printf("🔁 Sleeping for %ds...\n", cfg.IntervalSec)
		time.Sleep(time.Duration(cfg.IntervalSec) * time.Second)
	}
}
