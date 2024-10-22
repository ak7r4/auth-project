package main

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"

    _ "github.com/go-sql-driver/mysql"
    "golang.org/x/crypto/bcrypt"
)

// Structure to store database configuration
type Config struct {
    DB struct {
        Username string `json:"username"`
        Password string `json:"password"`
        Database string `json:"database"`
        Host     string `json:"host"`
        Port     string `json:"port"`
    } `json:"db"`
}

var db *sql.DB

// Function to load configurations from the JSON file
func loadConfig() (Config, error) {
    var config Config
    file, err := os.Open("config.json")
    if err != nil {
        return config, err
    }
    defer file.Close()

    decoder := json.NewDecoder(file)
    err = decoder.Decode(&config)
    if err != nil {
        return config, err
    }

    return config, nil
}

// Initializes the connection to the database
func initDB(config Config) {
    var err error
    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
        config.DB.Username, config.DB.Password, config.DB.Host, config.DB.Port, config.DB.Database)

    db, err = sql.Open("mysql", dsn)
    if err != nil {
        log.Fatal("Error connecting to the database:", err)
    }

    // Check the connection
    if err := db.Ping(); err != nil {
        log.Fatal("Error connecting to the database:", err)
    }
}

// Function to handle login
func handleLogin(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Get the form data
    username := r.FormValue("username")
    password := r.FormValue("password")

    // Here you should search for the user in the database and verify the password
    var storedHash string
    err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedHash)
    if err != nil {
        http.Error(w, "Incorrect username or password", http.StatusUnauthorized)
        return
    }

    // Verify the password
    err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
    if err != nil {
        http.Error(w, "Incorrect username or password", http.StatusUnauthorized)
        return
    }

    // Redirect to a success page or another action
    http.Redirect(w, r, "/Success", http.StatusSeeOther)
}

func main() {
    // Load database configuration
    config, err := loadConfig()
    if err != nil {
        log.Fatal("Error loading configurations:", err)
    }

    // Initialize the database
    initDB(config)

    // Route to serve the login page
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "page.html")
    })

    http.HandleFunc("/Success", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "authenticated.html")
    })

    // Route for login
    http.HandleFunc("/login", handleLogin)

    // Start the server on port 8080
    log.Println("Server running on port 8080...")
    http.ListenAndServe(":8080", nil)
}
