package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	_ "github.com/lib/pq"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "server"
	password = "Password?"
	dbname   = "server"
)

var (
	db                *sql.DB
	mux               *http.ServeMux
	currentAllowedIPs []string
	expectedIP        = "10.0.0.3"
	serverPublicKey   = "G5yLhW7MASCFF866wSXkDxj9l/Nw3X1zgNn+AVMeaQQ="
)

// Message определяет структуру для сообщений, хранимых в базе данных
type Message struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}

// IPRecord Объявление типа IPRecord и функций для работы с IP адресами
type IPRecord struct {
	IP        string    `json:"ip"`
	Timestamp time.Time `json:"timestamp"` // Добавляем поле для временной метки
}

// initDB инициализирует соединение с базой данных PostgreSQL.
func initDB() *sql.DB {
	// Формирование строки подключения к базе данных
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	// Открытие соединения с базой данных
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal("Error opening database:", err)
	}
	// Проверка соединения с базой данных
	if err := db.Ping(); err != nil {
		log.Fatal("Error connecting to database:", err)
	}
	fmt.Println("Successfully connected to database")
	return db
}

// helloHandler обрабатывает GET запросы, принимающие простое приветствие.
func helloHandler(w http.ResponseWriter, r *http.Request) {
	// Проверка на метод GET
	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
		return
	}
	// Чтение тела запроса
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	fmt.Println("Received request with body:", string(body))
	fmt.Fprintf(w, "Hello!")
	defer r.Body.Close()
}

// updatedIPsHandler обрабатывает запросы для получения обновленных IP адресов.
func updatedIPsHandler(w http.ResponseWriter, r *http.Request) {
	// Получение временной метки из параметров запроса
	clientTimestamp := r.URL.Query().Get("timestamp")
	fmt.Println("Received timestamp:", clientTimestamp)
	if clientTimestamp == "" {
		http.Error(w, "Timestamp parameter is missing", http.StatusBadRequest)
		return
	}

	// Парсинг временной метки
	clientTime, err := time.Parse(time.RFC3339, clientTimestamp)
	if err != nil {
		http.Error(w, "Invalid timestamp format", http.StatusBadRequest)
		return
	}

	// Запрос к базе данных для получения обновленных IP адресов
	rows, err := db.Query("SELECT ip, timestamp FROM ip_addresses WHERE timestamp > $1", clientTime)
	if err != nil {
		log.Printf("Failed to retrieve updated IPs: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Сбор данных из результатов запроса
	var ips []IPRecord
	for rows.Next() {
		var ip IPRecord
		if err := rows.Scan(&ip.IP, &ip.Timestamp); err != nil {
			log.Printf("Error scanning IPs: %v", err)
			continue
		}
		ips = append(ips, ip)
	}

	// Обработка пустого массива IP адресов
	if len(ips) == 0 {
		log.Println("No new IPs to send, sending empty array")
	}

	// Проверка на ошибки при чтении результатов запроса
	if err := rows.Err(); err != nil {
		log.Printf("Error retrieving rows: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Формирование и отправка ответа
	response, err := json.Marshal(ips)
	if err != nil {
		log.Printf("Failed to marshal IPs: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

// allowedIPsHandler возвращает текущий список разрешенных IP адресов в формате JSON.
func allowedIPsHandler(w http.ResponseWriter, r *http.Request) {
	// Проверка на метод GET
	if r.Method != "GET" {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}
	// Формирование ответа
	response, err := json.Marshal(currentAllowedIPs)
	if err != nil {
		log.Printf("Failed to marshal AllowedIPs: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

// getMessages обрабатывает GET запросы и извлекает все сообщения из базы данных.
func getMessages(w http.ResponseWriter, r *http.Request) {
	// Выполнение SQL запроса для получения всех сообщений
	rows, err := db.Query("SELECT id, content FROM messages")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close() //  закрытие соединения по завершении функции

	var messages []Message // Список для хранения сообщений
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.Content); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		messages = append(messages, m)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Кодирование списка сообщений в формате JSON и отправка клиенту
	json.NewEncoder(w).Encode(messages)
}

// handleRequests инициализирует маршрутизатор и регистрирует функции обработчиков.
func handleRequests(mux *http.ServeMux) {
	mux.HandleFunc("/", redirectToHTTPS)
	mux.HandleFunc("/hello", helloHandler)
	mux.HandleFunc("/allowed-ips", allowedIPsHandler)
	mux.HandleFunc("/updated-ips", updatedIPsHandler) // Обработчик для запросов обновленных IP адресов
	mux.HandleFunc("/wireguard-config", keyConfigHandler)
	// Регистрация обработчика сообщений с поддержкой методов GET и POST
	// Регистрация обработчика сообщений с поддержкой методов GET и POST
	mux.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			getMessages(w, r)
		case "POST":
			postMessage(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	// Обработчик для изменения или удаления конкретного сообщения
	mux.HandleFunc("/messages/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			getMessages(w, r)
		case "PUT":
			putMessage(w, r)
		case "DELETE":
			deleteMessage(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

// postMessage обрабатывает POST запросы для добавления нового сообщения в базу данных
func postMessage(w http.ResponseWriter, r *http.Request) {
	var m Message
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	// Выполнение SQL запроса на добавление нового сообщения
	_, err := db.Exec("INSERT INTO messages (id, content) VALUES ($1, $2)", m.ID, m.Content)
	if err != nil {
		log.Printf("Error inserting new message: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else {
		log.Printf("New message added: %v", m)
		fmt.Fprintf(w, "Message added")
	}
}

// putMessage обрабатывает PUT запросы для обновления содержимого существующего сообщения по его ID.
func putMessage(w http.ResponseWriter, r *http.Request) {
	// Извлекаем ID сообщения из URL
	id := r.URL.Path[len("/messages/"):]
	var updated Message
	// Декодирование тела запроса в структуру Message
	if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	// Выполнение SQL запроса для обновления содержимого сообщения по его ID
	_, err := db.Exec("UPDATE messages SET content = $1 WHERE id = $2", updated.Content, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Message updated")
}

// deleteMessage обрабатывает DELETE запросы для удаления сообщения по его ID.
func deleteMessage(w http.ResponseWriter, r *http.Request) {
	// Извлекаем ID сообщения из URL
	id := r.URL.Path[len("/messages/"):]
	// Выполнение SQL запроса для удаления сообщения по ID
	_, err := db.Exec("DELETE FROM messages WHERE id = $1", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Message deleted")
}

// addIP добавляет новый IP адрес в базу данных или обновляет существующий записи.
// Она проверяет наличие IP адреса в базе данных и добавляет его, если такого еще нет.
func addIP(db *sql.DB, ip string) {
	ip = strings.TrimSpace(ip)       // Удаление пробельных символов с обеих сторон IP адреса
	ip = strings.TrimSuffix(ip, ",") // Удаление запятой, если она есть в конце

	// Проверка на валидность IP адреса
	if net.ParseIP(ip) == nil {
		log.Printf("Invalid IP address format: %s", ip)
		return
	}

	currentTime := time.Now()

	// Проверка на существование IP как с минусом, так и без
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM ip_addresses WHERE ip IN ($1, $2)", ip, "-"+ip).Scan(&count)
	if err != nil {
		log.Printf("Error checking IP existence: %v", err)
		return
	}

	if count > 0 {
		// Если IP существует, удаляем все его записи из базы данных
		_, err := db.Exec("DELETE FROM ip_addresses WHERE ip IN ($1, $2)", ip, "-"+ip)
		if err != nil {
			log.Printf("Error deleting existing IP(s): %v", err)
			return
		}
	}

	// Вставляем новый IP адрес с текущей временной меткой
	_, err = db.Exec("INSERT INTO ip_addresses (ip, timestamp) VALUES ($1, $2)", ip, currentTime)
	if err != nil {
		log.Printf("Error adding new IP: %v", err)
	} else {
		log.Println("IP added successfully")
		updateAllowedIPs() // Обновляем список разрешенных IP адресов после добавления нового
	}
}

// deleteIP удаляет IP адрес из базы данных или добавляет отрицательную запись для его блокировки.
func deleteIP(db *sql.DB, ip string) {
	ip = strings.TrimSpace(ip)       // Удаление пробельных символов с обеих сторон IP адреса
	ip = strings.TrimSuffix(ip, ",") // Удаление запятой, если она есть в конце

	if net.ParseIP(ip) == nil {
		log.Printf("Invalid IP address format: %s", ip)
		return
	}

	var exists bool

	// Проверяем существование IP адреса в базе данных
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM ip_addresses WHERE ip = $1)", ip).Scan(&exists)
	if err != nil {
		log.Printf("Error checking IP existence: %v", err)
		return
	}

	if exists {
		// Если IP существует, удаляем его
		_, err := db.Exec("DELETE FROM ip_addresses WHERE ip = $1", ip)
		if err != nil {
			log.Printf("Error deleting IP: %v", err)
			return
		}
		log.Println("IP deleted successfully")

		// Добавляем отрицательную запись для IP (например, для будущей блокировки)
		_, err = db.Exec("INSERT INTO ip_addresses (ip, timestamp) VALUES ($1, $2)", "-"+ip, time.Now())
		if err != nil {
			log.Printf("Error adding new negative IP: %v", err)
		} else {
			log.Println("Negative IP added successfully")
		}
	} else {
		log.Printf("IP to delete not found: %v", ip)
	}
}

// updateAllowedIPs обновляет глобальный список разрешенных IP адресов в системе.
func updateAllowedIPs() {
	ips, err := getIPs(db)
	if err != nil {
		log.Printf("Failed to retrieve IPs for AllowedIPs update: %v", err)
		return
	}

	var allowedIPs []string
	for _, ip := range ips {
		allowedIPs = append(allowedIPs, ip.IP+"/32")
	}

	currentAllowedIPs = allowedIPs // Сохраняем обновленный список разрешенных IP адресов
	log.Println("AllowedIPs updated successfully")
}

// getIPs извлекает список IP адресов из базы данных вместе с их временными метками.
func getIPs(db *sql.DB) ([]IPRecord, error) {
	// Обновляем запрос для получения IP и временной метки
	rows, err := db.Query("SELECT ip, timestamp FROM ip_addresses")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []IPRecord
	for rows.Next() {
		var ip IPRecord
		// Обновляем Scan для извлечения и временной метки
		if err := rows.Scan(&ip.IP, &ip.Timestamp); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// Функции для работы с HTTPS запросами (helloHandler, getMessages, postMessage, и т.д.)
func runConsole(db *sql.DB) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Console started. Enter 'startserver' to run the HTTPS server.")
	for {
		fmt.Print("Enter command (addip, deleteip, listip, startserver, adduser, generate-config, exit): ")
		scanner.Scan()
		command := scanner.Text()

		switch command {
		case "addip":
			fmt.Print("Enter IP address to add: ")
			scanner.Scan()
			ip := scanner.Text()
			addIP(db, ip)
		case "deleteip":
			fmt.Print("Enter IP address to delete: ")
			scanner.Scan()
			ip := scanner.Text()
			deleteIP(db, ip)
		case "listip":
			ips, err := getIPs(db)
			if err != nil {
				fmt.Println("Error listing IPs:", err)
				continue
			}
			for _, ip := range ips {
				// Вывод IP и временной метки
				fmt.Printf("IP: %s, Timestamp: %s\n", ip.IP, ip.Timestamp.Format("2006-01-02 15:04:05"))
			}
		case "startserver":
			go func() {
				tlsConfig := &tls.Config{
					MinVersion:               tls.VersionTLS12, // Минимальная версия TLS 1.2
					CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
					PreferServerCipherSuites: true, // Предпочтение шифров сервера
					CipherSuites: []uint16{
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					},
				}

				server := &http.Server{
					Addr:      ":8080",
					Handler:   mux,
					TLSConfig: tlsConfig,
				}

				// Запуск HTTPS сервера на порту 8080 (или любом другом порту)
				fmt.Println("HTTPS Server started on port 8080")
				log.Fatal(server.ListenAndServeTLS("cert1.pem", "key1.pem"))

			}()
		case "adduser":
			addUser(db)

		case "generate-config":
			err := generateAndPrintClientConfig()
			if err != nil {
				fmt.Printf("Failed to generate client config: %v\n", err)
			}
		case "exit":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Unknown command")
		}
	}
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
}

func main() {
	// Демонстрация использования функций шифрования и дешифрования
	encryptedPassword, iv, err := encryptString("secret123")
	if err != nil {
		fmt.Println("Encryption failed:", err)
		return
	}

	fmt.Println("Encrypted password:", encryptedPassword)
	fmt.Println("IV:", iv)

	decryptedPassword, err := decryptString(encryptedPassword, iv)
	if err != nil {
		fmt.Println("Decryption failed:", err)
		return
	}

	fmt.Println("Decrypted password:", decryptedPassword)

	db = initDB()
	defer db.Close()
	mux = http.NewServeMux()
	handleRequests(mux)
	runConsole(db)
}

// generateKeys генерирует новую пару ключей для WireGuard и возвращает приватный и публичный ключи.
func generateKeys() (privateKey, publicKey string, err error) {
	fmt.Println("Starting private key generation")
	cmd := exec.Command("wg", "genkey")
	privKeyOut, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to generate private key: %v, error: %s\n", err, string(privKeyOut))
		return "", "", fmt.Errorf("failed to generate private key: %v, output: %s", err, string(privKeyOut))
	}
	privateKey = strings.TrimSpace(string(privKeyOut)) // Удаляем лишние пробелы и символы новой строки
	fmt.Println("Private key generated successfully")

	fmt.Println("Starting public key generation")
	cmd = exec.Command("echo", privateKey)
	cmd2 := exec.Command("wg", "pubkey")

	// Создаем канал для передачи вывода из cmd в cmd2
	pipeReader, pipeWriter := io.Pipe()
	cmd.Stdout = pipeWriter
	cmd2.Stdin = pipeReader

	var cmd2Output []byte
	errChan := make(chan error, 1) // Буферизированный канал для избежания блокировки

	// Чтение вывода cmd2 асинхронно
	go func() {
		defer pipeReader.Close() // Убедимся, что reader закрывается после чтения
		cmd2Output, err = cmd2.CombinedOutput()
		errChan <- err
	}()

	// Запускаем cmd и закрываем pipeWriter после выполнения для корректного EOF для cmd2
	if err := cmd.Run(); err != nil {
		pipeWriter.Close() // Закрываем писатель для корректной передачи EOF
		return "", "", fmt.Errorf("failed to run echo command: %v", err)
	}
	pipeWriter.Close() // Обязательно закрываем писатель после cmd.Run()

	// Ждем завершения cmd2 и получаем результат
	err = <-errChan
	if err != nil {
		fmt.Printf("Failed to generate public key: %v, error: %s\n", err, string(cmd2Output))
		return "", "", fmt.Errorf("failed to generate public key: %v, output: %s", err, string(cmd2Output))
	}

	publicKey = strings.TrimSpace(string(cmd2Output))
	fmt.Println("Public key generated successfully")

	return privateKey, publicKey, nil
}

func updateServerConfig(publicKey, ip string) error {
	configPath := "/etc/wireguard/wg0.conf"
	newPeer := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", publicKey, ip)

	// Открываем файл в режиме добавления
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open WireGuard config file for writing: %v\n", err)
		return err
	}
	defer f.Close()

	// Добавляем новую конфигурацию клиента
	if _, err := f.WriteString(newPeer); err != nil {
		fmt.Printf("Failed to append new peer to WireGuard config: %v\n", err)
		return err
	}

	fmt.Println("WireGuard config updated successfully. New peer added.")
	return nil
}

func generateClientConfig(privateKey, serverPublicKey, serverAddress, ip string) (string, error) {
	// Определение пути к директории и файлу конфигурации
	configDir := "/etc/wireguard/clients/"
	configFileName := hex.EncodeToString([]byte(privateKey)) + ".conf"
	configPath := configDir + configFileName

	// Проверка наличия директории, создание если не существует
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		fmt.Printf("Directory %s does not exist, creating...\n", configDir)
		if err := os.MkdirAll(configDir, 0755); err != nil {
			fmt.Printf("Failed to create directory: %v\n", err)
			return "", fmt.Errorf("failed to create directory: %v", err)
		}
	}

	// Сгенерировать содержимое конфигурации клиента
	config := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/24\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:51830\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n", privateKey, ip, serverPublicKey, serverAddress)
	fmt.Printf("Generating client config for IP: %s\n", ip)

	// Запись файла конфигурации
	err := ioutil.WriteFile(configPath, []byte(config), 0644)
	if err != nil {
		fmt.Printf("Failed to write client config file: %v\n", err)
		return "", fmt.Errorf("failed to write client config file: %v", err)
	}

	fmt.Printf("Client config file written successfully at: %s\n", configPath)
	return configPath, nil
}

func restartWireGuard() error {
	fmt.Println("Restarting WireGuard service...")
	cmd := exec.Command("/bin/systemctl", "restart", "wg-quick@wg0")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Failed to restart WireGuard: %s, output: %s\n", err, string(output))
		return err
	}
	fmt.Println("WireGuard restarted successfully")
	return nil
}

func keyConfigHandler(w http.ResponseWriter, r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || ip != expectedIP {
		fmt.Printf("Access denied due to IP mismatch or error: %v\n", err)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		fmt.Println("Authorization header missing or malformed")
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		return
	}
	fmt.Printf("Received credentials username: %s, password: %s\n", username, password)

	// Захардкоденные учетные данные для тестирования
	//hardcodedUsername := "user"
	//hardcodedPassword := "root"

	if username != hardcodedUsername || password != hardcodedPassword {
		fmt.Println("Invalid credentials provided")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	fmt.Println("Credentials verified successfully")

	// Расчет доступного IP-адреса
	clientIP, err := findAvailableIP("/etc/wireguard/wg0.conf")
	if err != nil {
		fmt.Printf("No available IP addresses: %v\n", err)
		http.Error(w, "No available IP addresses", http.StatusInternalServerError)
		return
	}
	fmt.Printf("Assigned IP: %s to client\n", clientIP)

	// Генерация ключей
	privateKey, publicKey, err := generateKeys()
	if err != nil {
		fmt.Printf("Failed to generate keys: %v\n", err)
		http.Error(w, "Failed to generate keys", http.StatusInternalServerError)
		return
	}
	fmt.Println("Keys generated successfully")

	// Обновление конфигурации сервера
	if err := updateServerConfig(publicKey, clientIP); err != nil {
		fmt.Printf("Error updating server config: %v\n", err)
		http.Error(w, "Failed to update server config", http.StatusInternalServerError)
		return
	}

	// Перезапуск WireGuard для применения изменений
	if err := restartWireGuard(); err != nil {
		fmt.Printf("Error restarting WireGuard: %v\n", err)
		http.Error(w, "Failed to restart WireGuard", http.StatusInternalServerError)
		return
	}
	fmt.Println("WireGuard restarted successfully")

	// Генерация конфигурации клиента
	configPath, err := generateClientConfig(privateKey, serverPublicKey, "192.168.100.99", clientIP)
	if err != nil {
		fmt.Printf("Failed to create client config: %v\n", err)
		http.Error(w, "Failed to create client config", http.StatusInternalServerError)
		return
	}

	// Чтение содержимого файла конфигурации
	fileContent, err := ioutil.ReadFile(configPath)
	if err != nil {
		fmt.Printf("Failed to read client config file: %v\n", err)
		http.Error(w, "Failed to read client config file", http.StatusInternalServerError)
		return
	}
	fmt.Println("Client configuration file read successfully.")

	w.Header().Set("Content-Type", "application/text")
	w.WriteHeader(http.StatusOK)
	w.Write(fileContent) // Отправляем содержимое файла
	fmt.Println("Client configuration sent successfully.")
}

func findAvailableIP(configPath string) (string, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	usedIPs := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "AllowedIPs") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				ips := strings.Split(strings.TrimSpace(parts[1]), ",")
				for _, ip := range ips {
					ip = strings.TrimSpace(ip)
					// Отсекаем маску подсети, если она есть
					if slashIndex := strings.Index(ip, "/"); slashIndex != -1 {
						ip = ip[:slashIndex]
					}
					usedIPs[ip] = true
				}
			}
		}
	}

	for i := 4; i <= 254; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		if !usedIPs[ip] {
			return ip, nil
		}
	}

	return "", fmt.Errorf("no available IP addresses")
}

// CorrectKeySize принимает ключ в виде строки и возвращает ключ в правильном размере для AES.
func CorrectKeySize(keyString string) []byte {
	key := []byte(keyString)
	var keySizes = []int{16, 24, 32}
	for _, size := range keySizes {
		if len(key) == size {
			return key
		}
	}
	maxSize := keySizes[len(keySizes)-1]
	if len(key) < maxSize {
		return append(key, make([]byte, maxSize-len(key))...)
	}
	return key[:maxSize]
}

// encryptString шифрует строку с использованием AES-256 в режиме CFB и возвращает шифртекст вместе с IV.
func encryptString(plainText string) (cipherText string, ivString string, err error) {
	keyString := "12345678901234567890123456789012" // Захардкодированный ключ
	key := CorrectKeySize(keyString)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	plainData := []byte(plainText)
	cipherData := make([]byte, aes.BlockSize+len(plainData))
	iv := cipherData[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherData[aes.BlockSize:], plainData)
	cipherText = base64.StdEncoding.EncodeToString(cipherData[aes.BlockSize:])
	ivString = base64.StdEncoding.EncodeToString(iv)
	return cipherText, ivString, nil
}

// decryptString дешифрует строку, используя AES-256 в режиме CFB, принимая шифртекст и IV.
func decryptString(cipherText, ivString string) (plainText string, err error) {
	keyString := "12345678901234567890123456789012" // Захардкодированный ключ
	key := CorrectKeySize(keyString)
	cipherData, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	iv, err := base64.StdEncoding.DecodeString(ivString)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plainData := make([]byte, len(cipherData))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plainData, cipherData)
	plainText = string(plainData)
	return plainText, nil
}

// addUser запрашивает имя пользователя и пароль, шифрует пароль и сохраняет нового пользователя в базе данных.
func addUser(db *sql.DB) {
	fmt.Print("Enter username: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	username := scanner.Text()

	fmt.Print("Enter password: ")
	scanner.Scan()
	password := scanner.Text()

	encryptedPassword, _, err := encryptString(password) // Обновляем вызов функции с учетом новой сигнатуры
	if err != nil {
		fmt.Println("Failed to encrypt password:", err)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, encrypted_password) VALUES ($1, $2)", username, encryptedPassword)
	if err != nil {
		fmt.Println("Failed to add user:", err)
		return
	}

	fmt.Println("User added successfully")
}

func generateAndPrintClientConfig() error {
	// Генерация ключей
	privateKey, publicKey, err := generateKeys()
	if err != nil {
		log.Printf("Failed to generate keys: %v", err)
		return fmt.Errorf("failed to generate keys: %v", err)
	}

	// Генерация доступного IP адреса для клиента
	clientIP, err := findAvailableIP("/etc/wireguard/wg0.conf")
	if err != nil {
		log.Printf("No available IP addresses: %v", err)
		return fmt.Errorf("no available IP addresses: %v", err)
	}

	// Обновление конфигурации сервера
	if err := updateServerConfig(publicKey, clientIP); err != nil {
		log.Printf("Failed to update server config: %v", err)
		return fmt.Errorf("failed to update server config: %v", err)
	}

	// Перезапуск WireGuard для применения изменений
	if err := restartWireGuard(); err != nil {
		log.Printf("Failed to restart WireGuard: %v", err)
		return fmt.Errorf("failed to restart WireGuard: %v", err)
	}

	// Генерация конфигурации клиента
	clientConfig, err := generateClientConfig(privateKey, serverPublicKey, "192.168.100.99", clientIP)
	if err != nil {
		log.Printf("Failed to generate client config: %v", err)
		return fmt.Errorf("failed to generate client config: %v", err)
	}

	// Вывод конфигурации клиента в консоль
	fmt.Println("Generated client configuration:")
	fmt.Println(clientConfig)

	return nil
}
