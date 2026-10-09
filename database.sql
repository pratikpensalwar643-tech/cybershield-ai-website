CREATE DATABASE IF NOT EXISTS cyber_threat_db;
USE cyber_threat_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    source TEXT NOT NULL,
    prediction VARCHAR(50) NOT NULL,
    confidence DECIMAL(5,2) NOT NULL,
    INDEX idx_timestamp (timestamp),
    INDEX idx_prediction (prediction)
);

INSERT INTO threat_logs (timestamp, source, prediction, confidence) VALUES
(NOW(), '192.168.1.104 -> Port 22', 'Password/OTP Attack', 92.40),
(NOW(), 'mail.verify-paypal-secure.com', 'Phishing', 98.10),
(NOW(), 'user_download/update.exe', 'Malware', 89.50),
(NOW(), 'sender@unknown-domain.info', 'Suspicious Mail', 94.20),
(NOW(), '10.0.0.5 -> google.com', 'Safe', 99.90);
