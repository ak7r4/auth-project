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

// Estrutura para armazenar as configurações do banco de dados
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

// Função para carregar configurações do arquivo JSON
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

// Inicializa a conexão com o banco de dados
func initDB(config Config) {
    var err error
    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
        config.DB.Username, config.DB.Password, config.DB.Host, config.DB.Port, config.DB.Database)

    db, err = sql.Open("mysql", dsn)
    if err != nil {
        log.Fatal("Erro ao conectar ao banco de dados:", err)
    }

    // Verifica a conexão
    if err := db.Ping(); err != nil {
        log.Fatal("Erro ao conectar ao banco de dados:", err)
    }
}

// Função para lidar com o login
func handleLogin(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
        return
    }

    // Obtem os dados do formulário
    username := r.FormValue("username")
    password := r.FormValue("password")

    // Aqui você deve buscar o usuário no banco de dados e verificar a senha
    var storedHash string
    err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedHash)
    if err != nil {
        http.Error(w, "Usuário ou senha incorreta", http.StatusUnauthorized)
        return
    }

    // Verifica a senha
    err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
    if err != nil {
        http.Error(w, "Usuário ou senha incorreta", http.StatusUnauthorized)
        return
    }

    // Redireciona para uma página de sucesso ou outra ação
    http.Redirect(w, r, "/Success", http.StatusSeeOther)
}

func main() {
    // Carrega as configurações do banco de dados
    config, err := loadConfig()
    if err != nil {
        log.Fatal("Erro ao carregar configurações:", err)
    }

    // Inicializa o banco de dados
    initDB(config)

    // Rota para servir a página de login
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "pagina.html")
    })

    http.HandleFunc("/Success", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "autenticado.html")
    })

    // Rota para o login
    http.HandleFunc("/login", handleLogin)

    // Inicia o servidor na porta 8080
    log.Println("Servidor rodando na porta 8080...")
    http.ListenAndServe(":8080", nil)
}
