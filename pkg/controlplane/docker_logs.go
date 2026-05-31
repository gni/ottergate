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

const MaxLogFrameSize = 1048576

type NetworkInfo struct {
	IPAddress string `json:"IPAddress"`
}

type NetworkSettings struct {
	Networks map[string]NetworkInfo `json:"Networks"`
}

type DockerContainer struct {
	ID              string          `json:"Id"`
	Names           []string        `json:"Names"`
	State           string          `json:"State"`
	Image           string          `json:"Image"`
	NetworkSettings NetworkSettings `json:"NetworkSettings"`
}

type ContainerIpMap struct {
	sync.RWMutex
	Map map[string]string
}

var IPToName = &ContainerIpMap{
	Map: make(map[string]string),
}

type DockerLogStreamer struct {
	mu            sync.Mutex
	activeStreams map[string]context.CancelFunc
	httpClient    *http.Client
	socketPath    string
}

var Streamer = &DockerLogStreamer{
	activeStreams: make(map[string]context.CancelFunc),
	socketPath:    "/var/run/docker.sock",
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
	time.Sleep(3 * time.Second)

	if _, err := os.Stat(s.socketPath); os.IsNotExist(err) {
		audit.Logger.System("Container monitoring loop suspended: Docker socket interface is detached for containment safety boundaries.")
		return
	}

	audit.Logger.System("Docker socket listener started. Monitoring sandboxed container executions...")
	s.discoverAndStream(ctx)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.StopAll()
			return
		case <-ticker.C:
			if _, err := os.Stat(s.socketPath); os.IsNotExist(err) {
				s.StopAll()
				return
			}
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
		isOttergate := false
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		hostname, _ := os.Hostname()
		if hostname != "" && strings.HasPrefix(c.ID, hostname) {
			isOttergate = true
		}

		if strings.Contains(name, "ottergate-ottergate") {
			isOttergate = true
		}

		if isOttergate {
			continue
		}

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

	for id, cancel := range s.activeStreams {
		if !runningIds[id] {
			cancel()
			delete(s.activeStreams, id)
		}
	}
}

func (s *DockerLogStreamer) streamContainerLogs(ctx context.Context, id string, name string, ipAddress string) {
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
			header := make([]byte, 8)
			_, err := io.ReadFull(reader, header)
			if err != nil {
				return
			}
			size := binaryBigEndianUint32(header[4:8])
			if size > MaxLogFrameSize {
				audit.Logger.Error(fmt.Sprintf("Terminated log stream for container %s: frame size exception (%d bytes)", name, size))
				return
			}

			payload := make([]byte, size)
			_, err = io.ReadFull(reader, payload)
			if err != nil {
				return
			}

			line := strings.TrimSpace(string(payload))
			if line == "" {
				continue
			}

			line = cleanLogLine(line)

			if strings.Contains(line, "execve") || strings.Contains(line, "sys_enter_execve") {
				audit.Logger.AddCommandEvent(ipAddress, line)
			} else {
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
	_ = b[3]
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}

func cleanLogLine(line string) string {
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