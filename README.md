<h1>Login Page Project</h1><br>
Project created to improve my programming skills.<br>
This is a login page that has the following architecture:
<br><br><br>

![image](https://github.com/user-attachments/assets/68c52c9a-c838-41ab-b383-caec99a3dd6e)


How to set up your database as the application expects:
```
USE golang_api;
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);
CREATE TABLE sessions (
    cookie VARCHAR(255) PRIMARY KEY,  -- Alterado para VARCHAR com comprimento
    user_id TEXT,                     -- ID do usuário associado à sessão
    expires_at DATETIME,              -- Data e hora de expiração da sessão
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP -- Data e hora de criação da sessão
);
```
