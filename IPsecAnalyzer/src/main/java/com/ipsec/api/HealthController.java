package com.ipsec.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.sql.DataSource;
import java.sql.Connection;
import java.util.HashMap;
import java.util.Map;

@RestController
public class HealthController implements HealthIndicator {
    
    @Autowired(required = false)
    private DataSource dataSource;
    
    @GetMapping("/health")
    public ResponseEntity<?> getHealth() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "IPsec Analyzer");
        response.put("version", "1.0");
        response.put("timestamp", System.currentTimeMillis());
        
        if (dataSource != null) {
            try (Connection conn = dataSource.getConnection()) {
                response.put("database", "CONNECTED");
            } catch (Exception e) {
                response.put("database", "FAILED: " + e.getMessage());
            }
        } else {
            response.put("database", "NOT_CONFIGURED");
        }
        
        java.io.File cipherModel = new java.io.File("models/cipher_classifier.model");
        response.put("ml_model", cipherModel.exists() ? "LOADED" : "MISSING");
        
        return ResponseEntity.ok(response);
    }
    
    @Override
    public Health health() {
        if (dataSource != null) {
            try (Connection conn = dataSource.getConnection()) {
                return Health.up().withDetail("database", "PostgreSQL OK").build();
            } catch (Exception e) {
                return Health.down().withDetail("error", e.getMessage()).build();
            }
        }
        return Health.up().withDetail("database", "In-Memory / Optional").build();
    }
}
