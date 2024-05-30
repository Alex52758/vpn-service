package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	timeFilePath        = "./last_update_time.txt"
	certPath            = "./cert1.pem"             // Путь к файлу сертификата
	initialConfigPath   = "./initial_config"        // Путь к файлу-индикатору первого запуска
	wireguardConfigPath = "/etc/wireguard/wg0.conf" // Путь к конфигурации WireGuard
	serverIP            = "10.0.0.1"                // IP-адрес сервера
	wireguardServerIP   = "192.168.100.99"          // IP-адрес WireGuard сервера
)

type IPRecord struct {
	IP        string    `json:"ip"`
	Timestamp time.Time `json:"timestamp"`
}

func newTLSClient(certFile string) (*http.Client, error) {
	caCert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("could not read cert file: %s", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append cert to pool")
	}

	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &http.Client{Transport: transport}, nil
}

func ManageIPRoutes(ips []string, defaultInterface string, defaultGateway string) {
	for _, ip := range ips {
		routeExists := checkRouteExists(ip)
		if strings.HasPrefix(ip, "-") {
			ip = strings.TrimPrefix(ip, "-")
			if routeExists {
				log.Println("Deleting IP route for:", ip)
				cmd := exec.Command("ip", "route", "del", ip, "dev", defaultInterface)
				output, err := cmd.CombinedOutput()
				if err != nil {
					log.Println("Failed to delete IP route:", err, string(output))
				} else {
					log.Println("IP route deleted successfully for:", ip)
				}
			} else {
				log.Println("No route exists for:", ip, "nothing to delete.")
			}
		} else {
			if !routeExists {
				log.Println("Adding IP route for:", ip)
				cmd := exec.Command("ip", "route", "add", ip, "via", defaultGateway, "dev", defaultInterface)
				output, err := cmd.CombinedOutput()
				if err != nil {
					log.Println("Failed to add IP route:", err, string(output))
				} else {
					log.Println("IP route added successfully for:", ip)
				}
			} else {
				log.Println("Route already exists for:", ip, "no need to add.")
			}
		}
	}
}

func findDefaultRoute() (string, string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 && strings.Contains(lines[0], "default via") {
		fields := strings.Fields(lines[0])
		if len(fields) > 4 {
			devIndex := -1
			gatewayIndex := -1
			for i, field := range fields {
				if field == "dev" {
					devIndex = i + 1
				}
				if field == "via" {
					gatewayIndex = i + 1
				}
			}
			if devIndex != -1 && gatewayIndex != -1 && len(fields) > devIndex && len(fields) > gatewayIndex {
				return fields[devIndex], fields[gatewayIndex], nil
			}
		}
	}
	return "", "", fmt.Errorf("default route not found in the output")
}

func checkRouteExists(ip string) bool {
	ip = strings.TrimPrefix(ip, "-")
	cmd := exec.Command("ip", "route", "show", "exact", ip)
	output, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) == "" {
		return false
	}
	return true
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("Failed to run the application: %v", err)
	}
}

func run() error {
	if !checkRootPrivileges() {
		return fmt.Errorf("this program requires superuser privileges. Please run as root")
	}

	setupLogging()

	if isFirstRun() {
		log.Println("First run detected.")
		if err := handleFirstRun(); err != nil {
			return fmt.Errorf("failed to handle first run: %v", err)
		}
	}

	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("error determining the executable path: %v", err)
	}

	if err := setupAutostart(executablePath); err != nil {
		return fmt.Errorf("failed to set up autostart: %v", err)
	}

	/*	if err := configureWireGuard(); err != nil {
		return fmt.Errorf("failed to configure WireGuard: %v", err)
	}*/

	return runMainLogic()
}

func setupLogging() {
	logFile, err := os.OpenFile("/var/log/myclient.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	log.SetOutput(logFile)
	log.Println("Logging setup completed.")
}

func runMainLogic() error {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	// Определение маршрута по умолчанию
	defaultInterface, defaultGateway, err := findDefaultRoute()
	if err != nil {
		return fmt.Errorf("failed to find default route: %v", err)
	}
	log.Printf("Default interface: %s, Default gateway: %s", defaultInterface, defaultGateway)

	for {
		log.Println("Fetching updated IPs...")
		ips, err := updateIPs()
		if err != nil {
			log.Printf("Error updating IPs: %v", err)
		} else {
			// Настройка маршрутов
			ManageIPRoutes(ips, defaultInterface, defaultGateway)
		}
		select {
		case <-ticker.C:
		}
	}
}

func updateIPs() ([]string, error) {
	lastUpdateTime := readLastUpdateTime()
	ips, err := getUpdatedIPs(lastUpdateTime, certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get updated IPs: %v", err)
	}
	writeLastUpdateTime(time.Now())
	return ips, nil
}

func setupAutostart(executablePath string) error {
	serviceContent := fmt.Sprintf(`[Unit]
Description=Client Application for IP Management

[Service]
ExecStart=%s
Restart=always

[Install]
WantedBy=multi-user.target
`, executablePath)

	systemdPath := "/etc/systemd/system/myclient.service"
	if err := ioutil.WriteFile(systemdPath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service file: %v", err)
	}

	cmd := exec.Command("systemctl", "enable", "myclient.service")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable service: %s, %v", output, err)
	}
	log.Println("Service enabled successfully.")

	cmd = exec.Command("systemctl", "start", "myclient.service")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start service: %s, %v", output, err)
	}
	log.Println("Service started successfully.")

	return nil
}

func ensureDependencies() error {
	if _, err := exec.LookPath("wireguard"); err != nil {
		cmd := exec.Command("apt-get", "install", "-y", "wireguard")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to install WireGuard: %s, %v", output, err)
		}
		log.Println("WireGuard installed successfully.")
	}

	if _, err := exec.LookPath("nft"); err != nil {
		cmd := exec.Command("apt-get", "install", "-y", "nftables")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to install nftables: %s, %v", output, err)
		}
		log.Println("nftables installed successfully.")
	}

	return nil
}

func isFirstRun() bool {
	if _, err := os.Stat(initialConfigPath); os.IsNotExist(err) {
		return true
	}
	return false
}

func handleFirstRun() error {
	if err := ensureDependencies(); err != nil {
		log.Printf("failed to ensure dependencies: %v", err)
		return fmt.Errorf("failed to ensure dependencies: %v", err)
	}

	if err := requestLoginCredentials(); err != nil {
		log.Printf("failed to get login credentials: %v", err)
		return fmt.Errorf("failed to get login credentials: %v", err)
	}

	if err := configureWireGuard(); err != nil {
		log.Printf("failed to fetch configureWireGuard: %v", err)
		return fmt.Errorf("failed to fetch configureWireGuard: %v", err)
	}

	if err := fetchInitialConfig(); err != nil {
		log.Printf("failed to fetch initial config: %v", err)
		return fmt.Errorf("failed to fetch initial config: %v", err)
	}

	if err := ioutil.WriteFile(initialConfigPath, []byte("initial config done"), 0644); err != nil {
		log.Printf("failed to write initial config file: %v", err)
		return fmt.Errorf("failed to write initial config file: %v", err)
	}

	return nil
}

func configureWireGuard() error {
	initialConfig := fmt.Sprintf(`[Interface]
PrivateKey = EKU6z2vifu5ENgbWjdEU1y/eZigyvT9MIbyRaPTyh18=
Address = 10.0.0.3/32

[Peer]
PublicKey = G5yLhW7MASCFF866wSXkDxj9l/Nw3X1zgNn+AVMeaQQ=
Endpoint = %s:51830
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 20
`, wireguardServerIP)

	configCommand := fmt.Sprintf("echo '%s' > %s", strings.ReplaceAll(initialConfig, "'", "'\\''"), wireguardConfigPath)
	cmd := exec.Command("sh", "-c", configCommand)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to write initial WireGuard config via sh: %s, %v", output, err)
		return fmt.Errorf("failed to write initial WireGuard config via sh: %s, %v", output, err)
	}
	log.Println("WireGuard config file updated successfully.")

	// Принудительное сохранение изменений на диск
	cmd2 := exec.Command("sync")
	if output, err := cmd2.CombinedOutput(); err != nil {
		log.Printf("Failed to sync filesystem: %s, %v", output, err)
		return fmt.Errorf("failed to sync filesystem: %s, %v", output, err)
	}
	log.Println("Filesystem synced successfully.")

	// Перезапуск WireGuard для применения изменений
	cmd3 := exec.Command("systemctl", "restart", "wg-quick@wg0")
	output, err = cmd3.CombinedOutput()
	if err != nil {
		log.Printf("Failed to restart WireGuard: %s, %v", output, err)
		return fmt.Errorf("failed to restart WireGuard: %s, %v", output, err)
	}
	log.Println("WireGuard restarted successfully and configured with initial IP 10.0.0.3.")

	return nil
}

func requestLoginCredentials() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read username: %v", err)
	}
	username = strings.TrimSpace(username)

	fmt.Print("Enter password: ")
	password, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}
	password = strings.TrimSpace(password)

	os.Setenv("VPN_USERNAME", username)
	os.Setenv("VPN_PASSWORD", password)

	return nil
}

func fetchInitialConfig() error {
	client, err := newTLSClient(certPath)
	if err != nil {
		log.Printf("Failed to create TLS client: %v", err)
		return fmt.Errorf("failed to create TLS client: %v", err)
	}
	log.Println("TLS client created successfully.")

	username := os.Getenv("VPN_USERNAME")
	password := os.Getenv("VPN_PASSWORD")

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s:8080/wireguard-config", serverIP), nil)
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return fmt.Errorf("failed to create request: %v", err)
	}
	log.Println("Request created successfully.")

	req.SetBasicAuth(username, password)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching initial config: %v", err)
		return fmt.Errorf("error fetching initial config: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to fetch initial config: server returned status %s", resp.Status)
		return fmt.Errorf("failed to fetch initial config: server returned status %s", resp.Status)
	}
	log.Println("Initial config fetched successfully.")

	body, err := ioutil.ReadAll(resp.Body)
	log.Printf("Received config: %s\n", string(body))
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return fmt.Errorf("error reading response body: %v", err)
	}
	log.Println("Response body read successfully.")
	log.Printf("Writing WireGuard configuration to %s\n", wireguardConfigPath)

	if err := ioutil.WriteFile(wireguardConfigPath, body, 0600); err != nil {
		log.Printf("Failed to write WireGuard config: %v\n", err)
		return fmt.Errorf("failed to write WireGuard config: %v", err)
	}
	// Принудительное сохранение изменений на диск
	cmd3 := exec.Command("sync")
	if _, err := cmd3.CombinedOutput(); err != nil {
		log.Println("Failed to sync filesystem:", err)
		return err
	}
	log.Println("WireGuard config written successfully.")

	// Добавляем задержку перед перезапуском
	time.Sleep(5 * time.Second)

	cmd := exec.Command("systemctl", "restart", "wg-quick@wg0")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Failed to restart WireGuard: %s, %v", output, err)
		return fmt.Errorf("failed to restart WireGuard: %s, %v", output, err)
	}
	log.Println("WireGuard restarted successfully.")

	log.Println("Initial WireGuard config applied successfully.")
	return nil
}

func checkRootPrivileges() bool {
	cmd := exec.Command("id", "-u")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Failed to check user ID: %v", err)
		return false
	}
	return strings.TrimSpace(string(output)) == "0"
}

func readLastUpdateTime() time.Time {
	content, err := ioutil.ReadFile(timeFilePath)
	if err != nil {
		log.Println("Failed to read last update time, starting from zero.")
		return time.Time{}
	}
	lastUpdateTime, err := time.Parse(time.RFC3339, string(content))
	if err != nil {
		log.Println("Failed to parse last update time, starting from zero.")
		return time.Time{}
	}
	return lastUpdateTime
}

func writeLastUpdateTime(t time.Time) {
	tString := t.Format(time.RFC3339)
	if err := ioutil.WriteFile(timeFilePath, []byte(tString), 0644); err != nil {
		log.Printf("Failed to write last update time: %v", err)
	}
}

// Изменение функции getUpdatedIPs, чтобы возвращать []string
func getUpdatedIPs(lastUpdateTime time.Time, certFile string) ([]string, error) {
	client, err := newTLSClient(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS client: %v", err)
	}

	formattedTime := url.QueryEscape(lastUpdateTime.Format(time.RFC3339))
	urlString := fmt.Sprintf("https://%s:8080/updated-ips?timestamp=%s", serverIP, formattedTime)
	resp, err := client.Get(urlString)
	if err != nil {
		return nil, fmt.Errorf("error fetching updated IPs: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch updated IPs: server returned status %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var ipRecords []IPRecord
	if err := json.Unmarshal(body, &ipRecords); err != nil {
		return nil, fmt.Errorf("error decoding IPs: %v", err)
	}

	if len(ipRecords) == 0 {
		log.Println("No new IPs received from server.")
		return nil, nil
	}

	log.Println("Received updated IPs:")
	var ips []string
	for _, ipRecord := range ipRecords {
		log.Printf("IP: %s, Timestamp: %s\n", ipRecord.IP, ipRecord.Timestamp)
		ips = append(ips, ipRecord.IP)
	}

	return ips, nil
}
