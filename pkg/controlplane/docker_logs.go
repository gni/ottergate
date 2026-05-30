package controlplane

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"ottergate/pkg/audit"
)

type NetworkInfo struct {
	IPAddress string `json:"IPAddress"`
}

type NetworkSettings struct {
	Networks map[string]NetworkInfo `json:"Networks"`
}

type DockerContainer struct {
	ID              string           `json:"Id"`
	Names           []string         `json:"Names"`
	State           string           `json:"State"`
	Image           string           `json:"Image"`
	NetworkSettings NetworkSettings  `json:"NetworkSettings"`
}

type ContainerIpMap struct {
	sync.RWMutex
	Map map[string]string
}

var IPToName = &ContainerIpMap{
	Map: make(map[string]string),
}

type DockerLogStreamer struct {
	mu           sync.Mutex
	activeStreams map[string]context.CancelFunc
	httpClient   *http.Client
}

var Streamer = &DockerLogStreamer{
	activeStreams: make(map[string]context.CancelFunc),
	httpClient: &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				dialer := net.Dialer{}
				return dialer.DialContext(ctx, "unix", "/var/run/docker.sock")
			},
		},
	},
}

func (s *DockerLogStreamer) Start(ctx context.Context) {
	// Wait a bit on startup for docker socket
	time.Sleep(3 * time.Second)
	audit.Logger.System("Docker socket listener started. Monitoring sandboxed container executions...")

	// Run initial discovery immediately
	s.discoverAndStream(ctx)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.StopAll()
			return
		case <-ticker.C:
			s.discoverAndStream(ctx)
		}
	}
}

func (s *DockerLogStreamer) StopAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, cancel := range s.activeStreams {
		cancel()
		delete(s.activeStreams, id)
	}
}

func (s *DockerLogStreamer) discoverAndStream(parentCtx context.Context) {
	req, err := http.NewRequestWithContext(parentCtx, "GET", "http://localhost/containers/json", nil)
	if err != nil {
		audit.Logger.Error(fmt.Sprintf("Docker log discover: failed to create request: %s", err.Error()))
		return
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		audit.Logger.Error(fmt.Sprintf("Docker log discover: failed to call Unix socket: %s", err.Error()))
		return
	}
	defer resp.Body.Close()

	var containers []DockerContainer
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		audit.Logger.Error(fmt.Sprintf("Docker log discover: failed to decode containers JSON: %s", err.Error()))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	runningIds := make(map[string]bool)

	for _, c := range containers {
		// Ignore ottergate engine container itself
		isOttergate := false
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		// Robustly detect own container via hostname matching
		hostname, _ := os.Hostname()
		if hostname != "" && strings.HasPrefix(c.ID, hostname) {
			isOttergate = true
		}

		// Fallback name matches
		if strings.Contains(name, "ottergate-ottergate") {
			isOttergate = true
		}

		if isOttergate {
			continue
		}

		// Store IP mappings for this sandbox client
		var ipAddress string
		IPToName.Lock()
		for _, netInfo := range c.NetworkSettings.Networks {
			if netInfo.IPAddress != "" {
				IPToName.Map[netInfo.IPAddress] = name
				ipAddress = netInfo.IPAddress
			}
		}
		IPToName.Unlock()

		if ipAddress == "" {
			ipAddress = name
		}

		runningIds[c.ID] = true

		if _, active := s.activeStreams[c.ID]; !active {
			ctx, cancel := context.WithCancel(parentCtx)
			s.activeStreams[c.ID] = cancel
			audit.Logger.System(fmt.Sprintf("Discovered container %s (%s) IP %s. Starting log stream listener...", name, c.ID[:12], ipAddress))
			go s.streamContainerLogs(ctx, c.ID, name, ipAddress)
		}
	}

	// Clean up stopped streams
	for id, cancel := range s.activeStreams {
		if !runningIds[id] {
			cancel()
			delete(s.activeStreams, id)
		}
	}
}

func (s *DockerLogStreamer) streamContainerLogs(ctx context.Context, id string, name string, ipAddress string) {
	// Query logs: stdout, stderr, stream (follow), tail = 0 (only new logs)
	urlPath := fmt.Sprintf("http://localhost/containers/%s/logs?stdout=true&stderr=true&follow=true&tail=5", id)
	req, err := http.NewRequestWithContext(ctx, "GET", urlPath, nil)
	if err != nil {
		audit.Logger.Error(fmt.Sprintf("Docker logs for %s: failed to create request: %s", name, err.Error()))
		return
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		audit.Logger.Error(fmt.Sprintf("Docker logs for %s: failed to connect to logs stream: %s", name, err.Error()))
		return
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Docker stream logs use a Multiplexed frame format (8-byte header):
			// - [0] stream type: 0 = stdin, 1 = stdout, 2 = stderr
			// - [1, 2, 3] ignored
			// - [4, 5, 6, 7] payload size (uint32)
			header := make([]byte, 8)
			_, err := io.ReadFull(reader, header)
			if err != nil {
				return
			}
			size := binaryBigEndianUint32(header[4:8])
			payload := make([]byte, size)
			_, err = io.ReadFull(reader, payload)
			if err != nil {
				return
			}

			line := strings.TrimSpace(string(payload))
			if line == "" {
				continue
			}

			// Clean line of terminal escape characters if present
			line = cleanLogLine(line)

			// Check for gVisor trace (JSON or text containing execve/sys_enter_execve)
			if strings.Contains(line, "execve") || strings.Contains(line, "sys_enter_execve") {
				audit.Logger.AddCommandEvent(ipAddress, line)
			} else {
				// Record as generic sandbox action event
				audit.GlobalBuffer.Add(audit.LogEvent{
					Timestamp: time.Now(),
					Type:      "command",
					ClientIP:  ipAddress,
					Details:   line,
					Status:    "info",
					Target:    "output",
				})
			}
		}
	}
}

func binaryBigEndianUint32(b []byte) uint32 {
	_ = b[3] // bounds check hint to compiler
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}

func cleanLogLine(line string) string {
	// Simple ASCII clean
	var sb strings.Builder
	for _, r := range line {
		if r >= 32 && r <= 126 {
			sb.WriteRune(r)
		} else if r == '\t' || r == '\n' || r == '\r' {
			sb.WriteRune(' ')
		}
	}
	return strings.TrimSpace(sb.String())
}
