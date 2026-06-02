package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"ottergate/pkg/audit"
	"ottergate/pkg/config"
	"ottergate/pkg/controlplane"
	"ottergate/pkg/dns"
	"ottergate/pkg/proxy"
)

const CLI_VERSION = "0.1.15"

type OttergateDaemon struct {
	mu          sync.Mutex
	cfg         *config.ServerConfig
	dnsServer   *dns.DevDnsServer
	dnsHandler  *dns.DnsHandler
	httpHandler *proxy.HttpHandler
	sniProxy    *proxy.SniProxyService
}

func (zd *OttergateDaemon) Start(cfg *config.ServerConfig) error {
	zd.mu.Lock()
	defer zd.mu.Unlock()

	zd.cfg = cfg

	dnsServer := dns.NewDevDnsServer(cfg)
	dnsHandler := dns.NewDnsHandler(dnsServer, cfg)
	if err := dnsHandler.Start(); err != nil {
		return err
	}
	zd.dnsServer = dnsServer
	zd.dnsHandler = dnsHandler
	audit.Logger.System(fmt.Sprintf("DNS Listener actively enforcing Zero-Trust boundaries on port %d", cfg.Port))

	httpPort := 80
	if cfg.HttpPort != nil {
		httpPort = *cfg.HttpPort
	}
	httpHandler := proxy.NewHttpHandler(cfg)
	if err := httpHandler.Start(); err != nil {
		_ = dnsHandler.Stop()
		return err
	}
	zd.httpHandler = httpHandler
	audit.Logger.System(fmt.Sprintf("HTTP L7 Sandbox Router active on port %d", httpPort))

	httpsPort := 443
	if cfg.HttpsPort != nil {
		httpsPort = *cfg.HttpsPort
	}
	sniProxy := proxy.NewSniProxyService(cfg, httpHandler)
	if err := sniProxy.Start(); err != nil {
		_ = dnsHandler.Stop()
		_ = httpHandler.Stop()
		return err
	}
	zd.sniProxy = sniProxy
	audit.Logger.System(fmt.Sprintf("SNI Proxy active on port %d", httpsPort))

	return nil
}

func (zd *OttergateDaemon) Stop() {
	zd.mu.Lock()
	defer zd.mu.Unlock()

	if zd.dnsHandler != nil {
		_ = zd.dnsHandler.Stop()
		zd.dnsHandler = nil
	}
	if zd.httpHandler != nil {
		_ = zd.httpHandler.Stop()
		zd.httpHandler = nil
	}
	if zd.sniProxy != nil {
		_ = zd.sniProxy.Stop()
		zd.sniProxy = nil
	}
	zd.dnsServer = nil

	audit.Logger.System("Subsystems halted. Sockets closed.")
}

func getHomeConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".ottergate")
}

func ensureConfigDir(dir string) {
	_ = os.MkdirAll(dir, 0700)
}

func loadConfig(configPath string) (map[string]interface{}, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return make(map[string]interface{}), nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func saveConfig(configPath string, data map[string]interface{}) error {
	ensureConfigDir(filepath.Dir(configPath))
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, bytes, 0600)
}

func setDeepValue(m map[string]interface{}, path string, value string) {
	parts := strings.Split(path, ".")
	current := m
	for i := 0; i < len(parts)-1; i++ {
		part := parts[i]
		next, ok := current[part]
		if !ok {
			nextMap := make(map[string]interface{})
			current[part] = nextMap
			current = nextMap
		} else {
			nextMap, ok := next.(map[string]interface{})
			if !ok {
				nextMap = make(map[string]interface{})
				current[part] = nextMap
				current = nextMap
			} else {
				current = nextMap
			}
		}
	}

	last := parts[len(parts)-1]
	if value == "true" {
		current[last] = true
	} else if value == "false" {
		current[last] = false
	} else if num, err := strconv.Atoi(value); err == nil {
		current[last] = num
	} else {
		current[last] = value
	}
}

func printUsage() {
	fmt.Printf(`
ottergate core engine (v%s)
Usage: ottergate <command> [options]

Commands:
  init       Initialize the default configuration file at ~/.ottergate/config.json
  start      Boot the routing engine and control plane
  config     Manage configuration state

Config Commands:
  ottergate config view                  Print the current configuration
  ottergate config set <key> <value>       Set a configuration value using dot notation
                                       Example: ottergate config set port 53
                                       Example: ottergate config set controlPlane.port 8081

Global Options:
  --config, -c  Override path to configuration file (default: ~/.ottergate/config.json)
  --json        Output CLI command results in pure JSON format
`, CLI_VERSION)
	os.Exit(0)
}

func handleInit(configPath string, isJson bool) {
	if _, err := os.Stat(configPath); err == nil {
		if isJson {
			fmt.Println(`{"success":false,"error":"Configuration already exists"}`)
		} else {
			audit.Logger.Error(fmt.Sprintf("Configuration already exists at %s", configPath))
		}
		os.Exit(1)
	}

	defaultConf := map[string]interface{}{
		"port":              53,
		"httpPort":          80,
		"httpsPort":         443,
		"fallbackDns":       "1.1.1.1",
		"maxTcpConnections": 100,
		"tcpIdleTimeoutMs":  30000,
		"controlPlane": map[string]interface{}{
			"enabled":    true,
			"socketPath": filepath.Join(os.TempDir(), "ottergate-cp.sock"),
		},
		"firewall": map[string]interface{}{
			"defaultPolicy": "deny",
			"allowlist_ips": []string{"127.0.0.1"},
		},
		"hosts": map[string]interface{}{},
	}

	if err := saveConfig(configPath, defaultConf); err != nil {
		if isJson {
			fmt.Printf(`{"success":false,"error":%q}`, err.Error())
		} else {
			audit.Logger.Error(fmt.Sprintf("Failed to write configuration file at %s: %s", configPath, err.Error()))
		}
		os.Exit(1)
	}

	if isJson {
		data, _ := json.Marshal(defaultConf)
		fmt.Printf(`{"success":true,"action":"init","path":%q,"config":%s}\n`, configPath, string(data))
	} else {
		audit.Logger.System(fmt.Sprintf("Initialized secure default configuration at %s", configPath))
		audit.Logger.System("Security Notice: Default HTTP/HTTPS ports mapped to 80/443.")
		audit.Logger.System("If executing within a non-root sandbox, mutate config.json to unprivileged ports (e.g. 8080/8443) to prevent EACCES binding faults.")
	}
	os.Exit(0)
}

func handleConfig(configPath string, args []string, isJson bool) {
	if len(args) == 0 {
		printUsage()
	}

	subCmd := args[0]
	if subCmd == "view" {
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			if isJson {
				fmt.Println(`{"success":false,"error":"No configuration found. Run init first."}`)
			} else {
				audit.Logger.Error(fmt.Sprintf("No configuration found at %s. Run 'ottergate init' first.", configPath))
			}
			os.Exit(1)
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			os.Exit(1)
		}

		if isJson {
			var m map[string]interface{}
			_ = json.Unmarshal(data, &m)
			out, _ := json.Marshal(m)
			fmt.Println(string(out))
		} else {
			fmt.Println(string(data))
		}
		os.Exit(0)
	}

	if subCmd == "set" {
		if len(args) < 3 {
			if isJson {
				fmt.Println(`{"success":false,"error":"Missing key or value"}`)
			} else {
				audit.Logger.Error("Usage: ottergate config set <key> <value>")
			}
			os.Exit(1)
		}

		key := args[1]
		value := args[2]

		currentConfig, err := loadConfig(configPath)
		if err != nil {
			os.Exit(1)
		}

		setDeepValue(currentConfig, key, value)
		if err := saveConfig(configPath, currentConfig); err != nil {
			if isJson {
				fmt.Printf(`{"success":false,"error":%q}\n`, err.Error())
			} else {
				audit.Logger.Error(fmt.Sprintf("Failed to save config: %s", err.Error()))
			}
			os.Exit(1)
		}

		if isJson {
			fmt.Printf(`{"success":true,"action":"set","key":%q,"value":%q}\n`, key, value)
		} else {
			audit.Logger.System(fmt.Sprintf("Updated configuration: %s = %s", key, value))
		}
		os.Exit(0)
	}

	printUsage()
}

func startEngine(configPath string, portOverride string, cpPortOverride string) {
	currentConfig, err := loadConfig(configPath)
	if err != nil {
		audit.Logger.Error(fmt.Sprintf("Failed to load config: %s", err.Error()))
		os.Exit(1)
	}

	if portOverride != "" {
		if port, err := strconv.Atoi(portOverride); err == nil {
			currentConfig["port"] = port
		}
	}

	if cpPortOverride != "" {
		cpMap, ok := currentConfig["controlPlane"].(map[string]interface{})
		if !ok {
			cpMap = make(map[string]interface{})
			currentConfig["controlPlane"] = cpMap
		}
		if port, err := strconv.Atoi(cpPortOverride); err == nil {
			cpMap["port"] = port
		}
	}

	configBytes, err := json.Marshal(currentConfig)
	if err != nil {
		os.Exit(1)
	}

	serverConfig, err := config.ParseServerConfig(configBytes)
	if err != nil {
		audit.Logger.Error(fmt.Sprintf("Configuration Schema Violation: %s", err.Error()))
		os.Exit(1)
	}

	daemon := &OttergateDaemon{}
	if err := daemon.Start(serverConfig); err != nil {
		audit.Logger.Error(fmt.Sprintf("Fatal bind error during initialization: %s", err.Error()))
		os.Exit(1)
	}

	isCpEnabled := true
	if serverConfig.ControlPlane != nil && serverConfig.ControlPlane.Enabled != nil {
		isCpEnabled = *serverConfig.ControlPlane.Enabled
	}

	var cp *controlplane.ControlPlane
	if isCpEnabled {
		apiKey := ""
		if envKey := os.Getenv("OTTERGATE_API_KEY"); envKey != "" {
			apiKey = envKey
		} else if serverConfig.ControlPlane != nil {
			apiKey = serverConfig.ControlPlane.ApiKey
		}

		isEphemeralKey := false
		if apiKey == "" {
			tokenBytes := make([]byte, 16)
			_, _ = io.ReadFull(rand.Reader, tokenBytes)
			apiKey = hex.EncodeToString(tokenBytes)
			isEphemeralKey = true
		}

		saltBytes := make([]byte, 8)
		_, _ = io.ReadFull(rand.Reader, saltBytes)
		blindIndexSalt := hex.EncodeToString(saltBytes)

		cpPort := 8080
		socketPath := ""
		var tlsConfig *config.TlsConfig

		if serverConfig.ControlPlane != nil {
			if serverConfig.ControlPlane.Port != 0 {
				cpPort = serverConfig.ControlPlane.Port
			}
			socketPath = serverConfig.ControlPlane.SocketPath
			tlsConfig = serverConfig.ControlPlane.Tls
		}

		cp = controlplane.NewControlPlane(
			cpPort,
			socketPath,
			apiKey,
			blindIndexSalt,
			serverConfig,
			configPath,
			tlsConfig,
		)

		cp.Subscribe(func(newCfg *config.ServerConfig) {
			audit.Logger.System("Applying dynamic configuration update from Control Plane...")
			daemon.mu.Lock()
			oldCfg := daemon.cfg
			daemon.mu.Unlock()

			daemon.Stop()
			if err := daemon.Start(newCfg); err != nil {
				audit.Logger.Error(fmt.Sprintf("Failed to reload daemon with new configuration: %s. Attempting fallback state rollback...", err.Error()))
				if rollbackErr := daemon.Start(oldCfg); rollbackErr != nil {
					audit.Logger.Error(fmt.Sprintf("CRITICAL FAILURE: Fallback rollback failed. System is offline: %s", rollbackErr.Error()))
				}
			}
		})

		if err := cp.Start(); err != nil {
			audit.Logger.Error(fmt.Sprintf("Failed to start Control Plane: %s", err.Error()))
			daemon.Stop()
			os.Exit(1)
		}

		if isEphemeralKey {
			audit.Logger.System(fmt.Sprintf("[SECURITY] Generated Ephemeral API Key for this session: %s", apiKey))
			audit.Logger.System("[SECURITY] Do not lose this key. It will not be shown again.")
		} else {
			audit.Logger.System("[SECURITY] Control Plane using static API Key from configuration.")
		}
	}

	audit.Logger.System("Initialization complete. Awaiting connections...")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	audit.Logger.System(fmt.Sprintf("Interrupt received (%s). Initiating graceful connection draining sequence (10s bounds)...", sig.String()))

	forceExit := time.AfterFunc(10*time.Second, func() {
		audit.Logger.Error("Graceful drain timeout exceeded. Forcing engine termination.")
		os.Exit(1)
	})

	daemon.Stop()
	if cp != nil {
		_ = cp.Stop()
	}

	forceExit.Stop()
	audit.Logger.System("All boundaries offline. Process terminating cleanly.")
	os.Exit(0)
}

func main() {
	var configPath string
	var jsonMode bool
	var portOverride string
	var cpPortOverride string

	defaultConfigPath := filepath.Join(getHomeConfigDir(), "config.json")

	flag.StringVar(&configPath, "config", defaultConfigPath, "Override path to configuration file")
	flag.StringVar(&configPath, "c", defaultConfigPath, "Override path to configuration file (shorthand)")
	flag.BoolVar(&jsonMode, "json", false, "Output CLI command results in pure JSON format")
	flag.StringVar(&portOverride, "port", "", "Override DNS port")
	flag.StringVar(&portOverride, "p", "", "Override DNS port (shorthand)")
	flag.StringVar(&cpPortOverride, "cp-port", "", "Override Control Plane port")

	flag.CommandLine.Usage = printUsage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		printUsage()
	}

	audit.Logger.SetJsonMode(jsonMode)

	command := args[0]

	switch command {
	case "init":
		handleInit(configPath, jsonMode)
	case "config":
		handleConfig(configPath, args[1:], jsonMode)
	case "start":
		startEngine(configPath, portOverride, cpPortOverride)
	default:
		printUsage()
	}
}