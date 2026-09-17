-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    whitelisted_ip VARCHAR(45) NOT NULL,
    device_fingerprint VARCHAR(255) NOT NULL,
    account_locked BOOLEAN DEFAULT false,
    locked_until TIMESTAMP,
    failed_attempts INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Create login attempts audit table
CREATE TABLE IF NOT EXISTS login_attempts (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    device_fingerprint VARCHAR(255),
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(500),
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create analysis history table
CREATE TABLE IF NOT EXISTS analysis_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    pcap_filename VARCHAR(500),
    predicted_cipher VARCHAR(100),
    predicted_mode VARCHAR(50),
    risk_score DECIMAL(5,2),
    risk_level VARCHAR(20),
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(username);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_analysis_user ON analysis_history(user_id);

-- NO SEEDED USER HERE: the admin account is created at first boot by
-- AdminBootstrap with a randomly generated password (written once to
-- .admin-credentials, mode 600) or from the ADMIN_PASSWORD env variable.
-- Hardcoding a shared demo password in the seed was removed on purpose.
-- Existing deployments that already have their admin row are unaffected.

-- Create views for dashboards
CREATE OR REPLACE VIEW analysis_summary AS
SELECT 
    u.username,
    COUNT(ah.id) as total_analyses,
    AVG(ah.risk_score) as avg_risk,
    MAX(ah.analyzed_at) as last_analysis
FROM users u
LEFT JOIN analysis_history ah ON u.id = ah.user_id
GROUP BY u.id, u.username;
