package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type AuditLogger struct {
	mu        sync.RWMutex
	useJson   bool
	isTestEnv bool
	output    io.Writer
	errOutput io.Writer

	dnsQueries    uint64
	dnsBlocked    uint64
	httpRequests  uint64
	httpBlocked   uint64
	firewallDrops uint64
	systemEvents  uint64
	errors        uint64
}

var Logger = &AuditLogger{
	output:    os.Stdout,
	errOutput: os.Stderr,
	isTestEnv: strings.HasSuffix(os.Args[0], ".test") || os.Getenv("GO_ENV") == "test",
}

func (l *AuditLogger) SetJsonMode(enable bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.useJson = enable
}

func (l *AuditLogger) SetOutput(out io.Writer, errOut io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = out
	l.errOutput = errOut
}

func (l *AuditLogger) Sanitize(input string) string {
	var sb strings.Builder
	for _, r := range input {
		if r == '\r' || r == '\n' || r == '\t' {
			sb.WriteRune(' ')
		} else if r < 32 || r > 126 {
			sb.WriteString(fmt.Sprintf("\\x%02x", r))
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func (l *AuditLogger) getHumanTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func (l *AuditLogger) GetMetricsPrometheus() string {
	return strings.Join([]string{
		"# HELP ottergate_dns_queries_total Total DNS queries processed",
		"# TYPE ottergate_dns_queries_total counter",
		fmt.Sprintf("ottergate_dns_queries_total %d", atomic.LoadUint64(&l.dnsQueries)),
		"# HELP ottergate_dns_blocked_total Total DNS queries blocked by policy",
		"# TYPE ottergate_dns_blocked_total counter",
		fmt.Sprintf("ottergate_dns_blocked_total %d", atomic.LoadUint64(&l.dnsBlocked)),
		"# HELP ottergate_http_requests_total Total HTTP requests routed",
		"# TYPE ottergate_http_requests_total counter",
		fmt.Sprintf("ottergate_http_requests_total %d", atomic.LoadUint64(&l.httpRequests)),
		"# HELP ottergate_http_blocked_total Total HTTP requests blocked",
		"# TYPE ottergate_http_blocked_total counter",
		fmt.Sprintf("ottergate_http_blocked_total %d", atomic.LoadUint64(&l.httpBlocked)),
		"# HELP ottergate_firewall_drops_total Total connection drops across L3/L4/L7",
		"# TYPE ottergate_firewall_drops_total counter",
		fmt.Sprintf("ottergate_firewall_drops_total %d", atomic.LoadUint64(&l.firewallDrops)),
		"# HELP ottergate_errors_total Total system errors encountered",
		"# TYPE ottergate_errors_total counter",
		fmt.Sprintf("ottergate_errors_total %d", atomic.LoadUint64(&l.errors)),
	}, "\n") + "\n"
}

type dnsQuestionLog struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type dnsLogPayload struct {
	Timestamp   string           `json:"timestamp"`
	Level       string           `json:"level"`
	Component   string           `json:"component"`
	IP          string           `json:"ip"`
	Questions   []dnsQuestionLog `json:"questions"`
	Rcode       int              `json:"rcode"`
	Cached      bool             `json:"cached"`
	ResolvedIps []string         `json:"resolved_ips,omitempty"`
}

func (l *AuditLogger) DNS(ip string, questions []struct {
	Name string
	Type string
}, rcode int, cached bool, resolvedIps []string, isLocalDns bool) {
	atomic.AddUint64(&l.dnsQueries, uint64(len(questions)))
	if rcode == 5 || rcode == 3 {
		atomic.AddUint64(&l.dnsBlocked, uint64(len(questions)))
	}

	if l.isTestEnv {
		return
	}

	l.mu.RLock()
	useJson := l.useJson
	output := l.output
	l.mu.RUnlock()

	logType := "dns"
	if isLocalDns {
		logType = "localdns"
	}

	if useJson {
		logs := make([]dnsQuestionLog, len(questions))
		for i, q := range questions {
			logs[i] = dnsQuestionLog{Name: q.Name, Type: q.Type}
		}
		payload := dnsLogPayload{
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Level:       "INFO",
			Component:   strings.ToUpper(logType),
			IP:          ip,
			Questions:   logs,
			Rcode:       rcode,
			Cached:      cached,
			ResolvedIps: resolvedIps,
		}
		data, _ := json.Marshal(payload)
		fmt.Fprintln(output, string(data))
	} else {
		codeMap := map[int]string{
			0: "allowed",
			1: "format error",
			2: "server failure",
			3: "domain not found",
			5: "refused by firewall",
		}
		prefix := ""
		if cached {
			prefix = "cached "
		}
		clock := l.getHumanTime()
		sanitizedIp := l.Sanitize(ip)
		resolvedSuffix := ""
		if len(resolvedIps) > 0 {
			resolvedSuffix = " [" + strings.Join(resolvedIps, ", ") + "]"
		}
		for _, q := range questions {
			status, ok := codeMap[rcode]
			if !ok {
				status = fmt.Sprintf("%d", rcode)
			}

			cLogType := logType
			if logType == "localdns" {
				cLogType = "\033[1;36mlocaldns\033[0m" // Bold Cyan
			} else {
				cLogType = "\033[36mdns\033[0m" // Cyan
			}
			cStatus := status
			if rcode == 0 {
				cStatus = "\033[32m" + status + "\033[0m" // Green
			} else {
				cStatus = "\033[31m" + status + "\033[0m" // Red
			}

			fmt.Fprintf(output, "[%s] [%s] %s requested %s%s record for %s -> %s%s\n",
				clock, cLogType, sanitizedIp, prefix, strings.ToUpper(q.Type), l.Sanitize(q.Name), cStatus, resolvedSuffix)

			evStatus := "allow"
			if rcode == 5 || rcode == 3 {
				evStatus = "deny"
			}
			GlobalBuffer.Add(LogEvent{
				Timestamp: time.Now(),
				Type:      logType,
				ClientIP:  sanitizedIp,
				Details:   fmt.Sprintf("Requested %s%s record%s", prefix, strings.ToUpper(q.Type), resolvedSuffix),
				Status:    evStatus,
				Target:    l.Sanitize(q.Name),
			})
		}
	}
}

type firewallLogPayload struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Component string `json:"component"`
	Action    string `json:"action"`
	IP        string `json:"ip"`
	Target    string `json:"target"`
	Detail    string `json:"detail"`
}

func (l *AuditLogger) Firewall(ip string, target string, action string, detail string) {
	if action == "DENY" {
		atomic.AddUint64(&l.firewallDrops, 1)
	}

	if l.isTestEnv {
		return
	}

	l.mu.RLock()
	useJson := l.useJson
	output := l.output
	l.mu.RUnlock()

	if useJson {
		level := "INFO"
		if action == "DENY" {
			level = "WARN"
		}
		payload := firewallLogPayload{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Level:     level,
			Component: "FIREWALL",
			Action:    action,
			IP:        ip,
			Target:    target,
			Detail:    detail,
		}
		data, _ := json.Marshal(payload)
		fmt.Fprintln(output, string(data))
	} else {
		cStatus := "\033[32mpassed\033[0m" // Green
		if action == "DENY" {
			cStatus = "\033[31mblocked\033[0m" // Red
		}
		extra := ""
		if detail != "" {
			extra = " due to " + detail
		}
		cComp := "\033[33mfirewall\033[0m" // Yellow
		fmt.Fprintf(output, "[%s] [%s] connection from %s targeting %s was %s%s\n",
			l.getHumanTime(), cComp, l.Sanitize(ip), l.Sanitize(target), cStatus, extra)

		evStatus := "allow"
		if action == "DENY" {
			evStatus = "deny"
		}
		GlobalBuffer.Add(LogEvent{
			Timestamp: time.Now(),
			Type:      "firewall",
			ClientIP:  l.Sanitize(ip),
			Details:   l.Sanitize(detail),
			Status:    evStatus,
			Target:    l.Sanitize(target),
		})
	}
}

type httpLogPayload struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Component string `json:"component"`
	IP        string `json:"ip"`
	Method    string `json:"method"`
	Host      string `json:"host"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Target    string `json:"target"`
}

func (l *AuditLogger) HTTP(ip string, method string, host string, path string, status int, target string) {
	atomic.AddUint64(&l.httpRequests, 1)
	if status == 403 || status == 413 || status == 429 {
		atomic.AddUint64(&l.httpBlocked, 1)
	}

	if l.isTestEnv {
		return
	}

	l.mu.RLock()
	useJson := l.useJson
	output := l.output
	l.mu.RUnlock()

	if useJson {
		level := "INFO"
		if status >= 400 {
			level = "WARN"
		}
		payload := httpLogPayload{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Level:     level,
			Component: "HTTP",
			IP:        ip,
			Method:    method,
			Host:      host,
			Path:      path,
			Status:    status,
			Target:    target,
		}
		data, _ := json.Marshal(payload)
		fmt.Fprintln(output, string(data))
	} else {
		routeInfo := "processed natively"
		if target != "" {
			sanTarget := l.Sanitize(target)
			if strings.HasPrefix(sanTarget, "Tunneled") || strings.HasPrefix(sanTarget, "Blocked") {
				routeInfo = sanTarget
			} else {
				routeInfo = "forwarded to " + sanTarget
			}
		}
		cComp := "\033[35mhttp\033[0m" // Magenta
		cStatus := fmt.Sprintf("%d", status)
		if status >= 400 {
			cStatus = "\033[31m" + cStatus + "\033[0m" // Red
		} else {
			cStatus = "\033[32m" + cStatus + "\033[0m" // Green
		}
		fmt.Fprintf(output, "[%s] [%s] %s | %s %s%s status %s | %s\n",
			l.getHumanTime(), cComp, l.Sanitize(ip), l.Sanitize(method), l.Sanitize(host), l.Sanitize(path), cStatus, routeInfo)

		evStatus := "allow"
		if status >= 400 {
			evStatus = "deny"
		}
		detailsStr := fmt.Sprintf("%s %s%s status %d", l.Sanitize(method), l.Sanitize(host), l.Sanitize(path), status)
		if method == "TLS-SNI" {
			detailsStr = fmt.Sprintf("TLS-SNI %s%s status %d", l.Sanitize(host), l.Sanitize(path), status)
		}
		if routeInfo != "" {
			detailsStr = fmt.Sprintf("%s | %s", detailsStr, routeInfo)
		}
		GlobalBuffer.Add(LogEvent{
			Timestamp: time.Now(),
			Type:      "http",
			ClientIP:  l.Sanitize(ip),
			Details:   detailsStr,
			Status:    evStatus,
			Target:    l.Sanitize(host),
		})
	}
}

type systemLogPayload struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Component string `json:"component"`
	Message   string `json:"message"`
}

func (l *AuditLogger) System(msg string) {
	atomic.AddUint64(&l.systemEvents, 1)
	if l.isTestEnv {
		return
	}

	l.mu.RLock()
	useJson := l.useJson
	output := l.output
	l.mu.RUnlock()

	if useJson {
		payload := systemLogPayload{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Level:     "INFO",
			Component: "SYSTEM",
			Message:   msg,
		}
		data, _ := json.Marshal(payload)
		fmt.Fprintln(output, string(data))
	} else {
		cComp := "\033[1;37msystem\033[0m" // Bold White
		fmt.Fprintf(output, "[%s] [%s] %s\n", l.getHumanTime(), cComp, l.Sanitize(msg))
		GlobalBuffer.Add(LogEvent{
			Timestamp: time.Now(),
			Type:      "system",
			ClientIP:  "localhost",
			Details:   l.Sanitize(msg),
			Status:    "info",
			Target:    "system",
		})
	}
}

func (l *AuditLogger) Error(msg string) {
	atomic.AddUint64(&l.errors, 1)
	if l.isTestEnv {
		return
	}

	l.mu.RLock()
	useJson := l.useJson
	errOutput := l.errOutput
	l.mu.RUnlock()

	if useJson {
		payload := systemLogPayload{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Level:     "ERROR",
			Component: "SYSTEM",
			Message:   msg,
		}
		data, _ := json.Marshal(payload)
		fmt.Fprintln(errOutput, string(data))
	} else {
		cComp := "\033[1;31merror\033[0m" // Bold Red
		fmt.Fprintf(errOutput, "[%s] [%s] %s\n", l.getHumanTime(), cComp, l.Sanitize(msg))
		GlobalBuffer.Add(LogEvent{
			Timestamp: time.Now(),
			Type:      "error",
			ClientIP:  "localhost",
			Details:   l.Sanitize(msg),
			Status:    "error",
			Target:    "error",
		})
	}
}

type commandLogPayload struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Component string `json:"component"`
	IP        string `json:"ip"`
	Command   string `json:"command"`
}

func (l *AuditLogger) Command(ip string, command string) {
	atomic.AddUint64(&l.systemEvents, 1)
	if l.isTestEnv { return }

	l.mu.RLock()
	useJson := l.useJson
	output := l.output
	l.mu.RUnlock()

	if useJson {
		payload := commandLogPayload{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Level:     "INFO",
			Component: "EXEC",
			IP:        ip,
			Command:   command,
		}
		data, _ := json.Marshal(payload)
		fmt.Fprintln(output, string(data))
	} else {
		cComp := "\033[34mexecve\033[0m" // Blue
		fmt.Fprintf(output, "[%s] [%s] %s executed: %s\n", l.getHumanTime(), cComp, l.Sanitize(ip), l.Sanitize(command))
		
		GlobalBuffer.Add(LogEvent{
			Timestamp: time.Now(),
			Type:      "command",
			ClientIP:  l.Sanitize(ip),
			Details:   l.Sanitize(command),
			Status:    "info",
			Target:    "execve",
		})
	}
}

func (l *AuditLogger) ContainerOutput(ip string, log string) {
	atomic.AddUint64(&l.systemEvents, 1)
	if l.isTestEnv { return }

	l.mu.RLock()
	useJson := l.useJson
	output := l.output
	l.mu.RUnlock()

	if useJson {
		payload := commandLogPayload{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Level:     "INFO",
			Component: "STDOUT",
			IP:        ip,
			Command:   log,
		}
		data, _ := json.Marshal(payload)
		fmt.Fprintln(output, string(data))
	} else {
		cComp := "\033[36mstdout\033[0m" // Cyan
		fmt.Fprintf(output, "[%s] [%s] %s | %s\n", l.getHumanTime(), cComp, l.Sanitize(ip), l.Sanitize(log))
		
		GlobalBuffer.Add(LogEvent{
			Timestamp: time.Now(),
			Type:      "command",
			ClientIP:  l.Sanitize(ip),
			Details:   l.Sanitize(log),
			Status:    "info",
			Target:    "output",
		})
	}
}