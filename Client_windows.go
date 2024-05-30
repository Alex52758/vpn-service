package main

import (
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
	timeFilePath = "./last_update_time.txt"
	certPath     = "./cert1.pem" // Путь к файлу сертификата
	serverIP     = "10.0.0.1"    // IP-адрес сервера
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
				cmd := exec.Command("route", "delete", ip)
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
				cmd := exec.Command("route", "add", ip, defaultGateway)
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
	cmd := exec.Command("powershell", "-Command", "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object -Property RouteMetric | Select-Object InterfaceAlias,NextHop,RouteMetric | Format-Table -HideTableHeaders")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", err
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] != "On-link" {
			return fields[0], fields[1], nil
		}
	}

	return "", "", fmt.Errorf("default route not found in the output")
}

func checkRouteExists(ip string) bool {
	ip = strings.TrimPrefix(ip, "-")
	cmd := exec.Command("powershell", "Get-NetRoute", "-DestinationPrefix", ip)
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
	if !checkAdminPrivileges() {
		return fmt.Errorf("this program requires administrator privileges. Please run as administrator")
	}

	setupLogging()

	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("error determining the executable path: %v", err)
	}

	if err := setupAutostart(executablePath); err != nil {
		return fmt.Errorf("failed to set up autostart: %v", err)
	}

	return runMainLogic()
}

func setupLogging() {
	logFile, err := os.OpenFile("C:\\ProgramData\\myclient.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	log.SetOutput(logFile)
	log.Println("Logging setup completed.")
}

func runMainLogic() error {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

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
	taskName := "MyClientAutostart"
	executablePath = fmt.Sprintf("\"%s\"", executablePath) // Заключаем путь в кавычки
	cmd := exec.Command("schtasks", "/create", "/tn", taskName, "/tr", executablePath, "/sc", "onlogon", "/rl", "highest", "/f")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create scheduled task: %v, %s", err, output)
	}
	log.Println("Scheduled task created successfully.")
	return nil
}

func checkAdminPrivileges() bool {
	cmd := exec.Command("powershell", "-Command", "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Failed to check user privileges: %v", err)
		return false
	}
	return strings.TrimSpace(string(output)) == "True"
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
