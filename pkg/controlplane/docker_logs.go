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
	"path/filepath"
	"regexp"
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
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Check if Docker socket exists/is active
	useDocker := true
	if _, err := os.Stat("/var/run/docker.sock"); os.IsNotExist(err) {
		useDocker = false
		audit.Logger.System("Docker socket not found at /var/run/docker.sock. Falling back to direct gVisor directory telemetry...")
	}

	if useDocker {
		audit.Logger.System("Initializing Docker socket telemetry connection...")

		for {
			req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/containers/json", nil)
			if err == nil {
				resp, err := s.httpClient.Do(req)
				if err == nil {
					if resp.StatusCode == http.StatusOK {
						resp.Body.Close()
						audit.Logger.System("Docker API connection established. Monitoring sandboxed container executions...")
						s.discoverAndStream(ctx)
						break
					} else {
						audit.Logger.Error(fmt.Sprintf("Docker API responded with HTTP %d during telemetry boot. Retrying...", resp.StatusCode))
					}
					resp.Body.Close()
				} else {
					audit.Logger.Error(fmt.Sprintf("Failed to dial Docker socket: %s. Retrying...", err.Error()))
				}
			} else {
				audit.Logger.Error(fmt.Sprintf("Failed to construct HTTP request for Docker socket: %s", err.Error()))
			}
			
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}

		for {
			select {
			case <-ctx.Done():
				s.StopAll()
				return
			case <-ticker.C:
				s.discoverAndStream(ctx)
			}
		}
	} else {
		// Non-Docker mode: directly scan gVisor trace log directories
		s.discoverAndStreamDirect(ctx)
		for {
			select {
			case <-ctx.Done():
				s.StopAll()
				return
			case <-ticker.C:
				s.discoverAndStreamDirect(ctx)
			}
		}
	}
}

func (s *DockerLogStreamer) discoverAndStreamDirect(parentCtx context.Context) {
	dir := "/var/log/gvisor"
	files, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	runningIds := make(map[string]bool)

	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		id := f.Name()
		if len(id) < 8 {
			continue
		}

		name := id
		if len(name) > 12 {
			name = name[:12]
		}
		ipAddress := name

		IPToName.Lock()
		IPToName.Map[ipAddress] = name
		IPToName.Unlock()

		runningIds[id] = true

		if _, active := s.activeStreams[id]; !active {
			ctx, cancel := context.WithCancel(parentCtx)
			s.activeStreams[id] = cancel
			audit.Logger.System(fmt.Sprintf("Discovered direct gVisor sandbox %s. Starting log stream listener...", name))
			go s.streamGvisorLogs(ctx, id, name, ipAddress)
		}
	}

	for id, cancel := range s.activeStreams {
		if !runningIds[id] {
			cancel()
			delete(s.activeStreams, id)
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
		return
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var containers []DockerContainer
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
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

		myHostname, _ := os.Hostname()
		if (myHostname != "" && strings.HasPrefix(c.ID, myHostname)) || 
		   (strings.Contains(name, "ottergate") && !strings.Contains(name, "client") && !strings.Contains(name, "backend")) {
			isOttergate = true
		}

		if isOttergate {
			continue
		}

		var ipAddress string
		hasIp := false
		
		IPToName.Lock()
		for _, netInfo := range c.NetworkSettings.Networks {
			if netInfo.IPAddress != "" {
				IPToName.Map[netInfo.IPAddress] = name
				ipAddress = netInfo.IPAddress
				hasIp = true
			}
		}
		
		if !hasIp {
			ipAddress = name
			IPToName.Map[ipAddress] = name
		}
		IPToName.Unlock()

		runningIds[c.ID] = true

		if _, active := s.activeStreams[c.ID]; !active {
			ctx, cancel := context.WithCancel(parentCtx)
			s.activeStreams[c.ID] = cancel
			audit.Logger.System(fmt.Sprintf("Discovered container %s (%s) IP %s. Starting log stream listener...", name, c.ID[:12], ipAddress))
			go s.streamContainerLogs(ctx, c.ID, name, ipAddress)
			go s.streamGvisorLogs(ctx, c.ID, name, ipAddress)
		}
	}

	for id, cancel := range s.activeStreams {
		if !runningIds[id] {
			cancel()
			delete(s.activeStreams, id)
		}
	}
}

func (s *DockerLogStreamer) streamGvisorLogs(ctx context.Context, id string, name string, ipAddress string) {
	dir := filepath.Join("/var/log/gvisor", id)
	tails := make(map[string]int64)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			files, err := filepath.Glob(filepath.Join(dir, "runsc.log.*"))
			if err != nil || len(files) == 0 {
				continue
			}
			for _, file := range files {
				info, err := os.Stat(file)
				if err != nil {
					continue
				}
				lastPos := tails[file]
				if info.Size() > lastPos {
					f, err := os.Open(file)
					if err == nil {
						_, _ = f.Seek(lastPos, io.SeekStart)
						scanner := bufio.NewScanner(f)
						for scanner.Scan() {
							line := strings.TrimSpace(scanner.Text())
							if line == "" {
								continue
							}
							if strings.Contains(line, "sys_execve") || 
							   strings.Contains(line, "sys_connect") || 
							   strings.Contains(line, "sys_socket") || 
							   strings.Contains(line, "sys_clone") || 
							   strings.Contains(line, "sys_ptrace") {
								audit.Logger.Command(ipAddress, "[gvisor-trace] " + cleanLogLine(line))
							}
						}
						tails[file] = info.Size()
						_ = f.Close()
					}
				}
			}
		}
	}
}

func (s *DockerLogStreamer) streamContainerLogs(ctx context.Context, id string, name string, ipAddress string) {
	defer func() {
		s.mu.Lock()
		delete(s.activeStreams, id)
		s.mu.Unlock()
	}()

	reqInspect, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://localhost/containers/%s/json", id), nil)
	if err != nil {
		return
	}
	respInspect, err := s.httpClient.Do(reqInspect)
	if err != nil {
		return
	}
	var inspect struct {
		Config struct {
			Tty bool `json:"Tty"`
		} `json:"Config"`
	}
	err = json.NewDecoder(respInspect.Body).Decode(&inspect)
	respInspect.Body.Close()
	if err != nil {
		return
	}
	isTty := inspect.Config.Tty

	urlPath := fmt.Sprintf("http://localhost/containers/%s/logs?stdout=true&stderr=true&follow=true&tail=5", id)
	req, err := http.NewRequestWithContext(ctx, "GET", urlPath, nil)
	if err != nil {
		return
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	processLine := func(line string) {
		line = cleanLogLine(line)
		if line == "" {
			return
		}
		if strings.Contains(line, "execve") || strings.Contains(line, "sys_enter_execve") {
			audit.Logger.Command(ipAddress, line)
		} else {
			audit.Logger.ContainerOutput(ipAddress, line)
		}
	}

	if isTty {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
				processLine(scanner.Text())
			}
		}
		return
	}

	reader := bufio.NewReader(resp.Body)
	var lineBuf strings.Builder

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
				return
			}

			payload := make([]byte, size)
			_, err = io.ReadFull(reader, payload)
			if err != nil {
				return
			}

			chunk := string(payload)
			for {
				idx := strings.IndexByte(chunk, '\n')
				if idx == -1 {
					if lineBuf.Len()+len(chunk) > 5242880 {
						lineBuf.Reset()
					} else {
						lineBuf.WriteString(chunk)
					}
					break
				}
				lineBuf.WriteString(chunk[:idx])
				processLine(lineBuf.String())
				lineBuf.Reset()
				chunk = chunk[idx+1:]
			}
		}
	}
}

func binaryBigEndianUint32(b []byte) uint32 {
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}

var (
	csiRegex = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)
	oscRegex = regexp.MustCompile(`\x1b\][^\x07\x1b\\]*(?:\x07|\x1b\\)`)
)

func cleanLogLine(line string) string {
	line = oscRegex.ReplaceAllString(line, "")
	line = csiRegex.ReplaceAllString(line, "")

	if idx := strings.LastIndexByte(line, '\r'); idx != -1 {
		line = line[idx+1:]
	}

	var sb strings.Builder
	for _, r := range line {
		if r >= 32 && r <= 126 {
			sb.WriteRune(r)
		} else if r == '\t' || r == '\n' {
			sb.WriteRune(' ')
		}
	}
	return strings.TrimSpace(sb.String())
}