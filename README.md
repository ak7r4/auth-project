<h1>Login Page Project</h1><br>
Project created to improve my programming skills.<br>
This is a login page that has the following architecture:
<br><br><br>

![image](https://github.com/user-attachments/assets/68c52c9a-c838-41ab-b383-caec99a3dd6e)


How to set up your database as the application expects:
```
CREATE DATABASE golang_api;
USE golang_api;
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);
CREATE TABLE sessions (
    cookie VARCHAR(255) PRIMARY KEY,
    user_id TEXT,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
