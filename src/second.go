package main

import (
    "database/sql"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "html/template"
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/gin-contrib/sessions"
    "github.com/gin-contrib/sessions/cookie"
    _ "github.com/go-sql-driver/mysql"
    "github.com/joho/godotenv"
    "golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// Initializes the connection to the database
func initDB() {
    var err error

    // Load environment variables from .env file in config directory
    envPath := filepath.Join("config", ".env")
    err = godotenv.Load(envPath)
    if err != nil {
        log.Fatal("Error loading .env file:", err)
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

// Renders an HTML page
func render(c *gin.Context, tmpl string, data gin.H) {
    t, err := template.ParseFiles(tmpl)
    if err != nil {
        c.String(http.StatusInternalServerError, "Template error")
        return
    }
    t.Execute(c.Writer, data)
}

// Middleware to ensure the user is authenticated
func authRequired(c *gin.Context) {
    session := sessions.Default(c)
    user := session.Get("user")
    if user == nil {
        log.Println("No active session, redirecting to /login")
        // Se o usuário não estiver autenticado, redireciona para /login
        c.Redirect(http.StatusSeeOther, "/login")
        c.Abort()
        return
    }
    log.Println("User authenticated:", user)
    // Se o usuário estiver autenticado, permite o acesso
    c.Next()
}

// Handle login logic
func handleLogin(c *gin.Context) {
    if c.Request.Method == http.MethodGet {
        render(c, "templates/pagina.html", gin.H{"ErrorMessage": ""})
        return
    }

    username := c.PostForm("username")
    password := c.PostForm("password")

    if username == "" || password == "" {
        render(c, "templates/pagina.html", gin.H{"ErrorMessage": "Usuário ou senha incorretos."})
        return
    }

    if len(username) > 50 || len(password) > 300 {
        render(c, "templates/pagina.html", gin.H{"ErrorMessage": "Usuário ou senha incorretos."})
        return
    }

    // Search for the user in the database
    var storedHash string
    err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedHash)
    if err != nil {
        render(c, "templates/pagina.html", gin.H{"ErrorMessage": "Usuário ou senha incorretos."})
        return
    }

    // Verify the password
    err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
    if err != nil {
        render(c, "templates/pagina.html", gin.H{"ErrorMessage": "Usuário ou senha incorretos."})
        return
    }

    // Store session
    session := sessions.Default(c)
    session.Set("user", username)
    if err := session.Save(); err != nil {
        log.Println("Erro ao salvar sessão:", err)
        render(c, "templates/pagina.html", gin.H{"ErrorMessage": "Erro ao salvar a sessão. Tente novamente."})
        return
    }

    log.Println("User logged in successfully:", username)
    // Redirect to success page
    c.Redirect(http.StatusSeeOther, "/success")
}

func handleLogout(c *gin.Context) {
    session := sessions.Default(c)
    session.Clear()  // Limpa todos os dados da sessão
    session.Save()   // Salva a sessão vazia para encerrar
    log.Println("User logged out")
    c.Redirect(http.StatusSeeOther, "/login")  // Redireciona para a página de login
}

func main() {
    // Initialize the database
    initDB()

    // Initialize the Gin router
    r := gin.Default()

    // Session store middleware (using cookie store for simplicity)
    store := cookie.NewStore([]byte("hjkasd123789hiduwsSDFFDVGFGHJ45634557689HGDHFGDGDZXFHJSDFGNDSdfgsdfgsdfg4356ergh456hsb324v45h5e67kjDFGSDFG345435yudZGDZFGSDFG"))
    store.Options(sessions.Options{
	Path:     "/",
	HttpOnly: true,
	Secure:   false,
	MaxAge:   50,
    })
    r.Use(sessions.Sessions("mysession", store))

    // Serve static files from the assets directory
    r.Static("/assets", "./assets")

    // Public routes
    r.GET("/login", handleLogin)
    r.POST("/login", handleLogin)

    // Protected routes (require authentication)
    r.GET("/success", authRequired, func(c *gin.Context) {
        render(c, "templates/autenticado.html", gin.H{})
    })
    r.POST("/success", authRequired, func(c *gin.Context) {
        render(c, "templates/autenticado.html", gin.H{})
    })

    // Protected routes (require authentication)
    r.POST("/change", authRequired, func(c *gin.Context) {
        log.Println("Acessando a rota /change")
        render(c, "templates/change.html", gin.H{});
    })
    r.GET("/change", func(c *gin.Context) {
        c.Redirect(http.StatusSeeOther, "/login")
    })

    // Root route redirects to login
    r.GET("/", func(c *gin.Context) {
        c.Redirect(http.StatusSeeOther, "/login")
    })

    // Root route redirects to signup
    r.GET("/signup", func(c *gin.Context) {
        render(c, "templates/signup.html", gin.H{})
    })

    r.POST("/logout", handleLogout)
    r.GET("/logout", func(c *gin.Context) {
        c.Redirect(http.StatusSeeOther, "/login")
    })

    // Start the server on port 8080
    log.Println("Server running on port 8080...")
    r.Run(":8080")

}
