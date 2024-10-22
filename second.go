package main

import (
    "database/sql"
    "fmt"
    "log"
    "net/http"
    "os"

    _ "github.com/go-sql-driver/mysql"
    "golang.org/x/crypto/bcrypt"
    "github.com/joho/godotenv"
)

var db *sql.DB

// Initializes the connection to the database
func initDB() {
    var err error

    // Load environment variables from .env file
    err = godotenv.Load()
    if err != nil {
        log.Fatal("Error loading .env file")
    }

    // Retrieve configuration from environment variables
    username := os.Getenv("DB_USERNAME")
    password := os.Getenv("DB_PASSWORD")
    database := os.Getenv("DB_DATABASE")
    host := os.Getenv("DB_HOST")
    port := os.Getenv("DB_PORT")

    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
        username, password, host, port, database)

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
    // Initialize the database
    initDB()

    // Route to serve the login page
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "pagina.html")
    })

    http.HandleFunc("/Success", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "autenticado.html")
    })

    // Route for login
    http.HandleFunc("/login", handleLogin)

    // Start the server on port 8080
    log.Println("Server running on port 8080...")
    http.ListenAndServe(":8080", nil)
}
