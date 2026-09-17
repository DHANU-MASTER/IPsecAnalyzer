package com.ipsec.security.controller;

import com.ipsec.security.service.SecurityBlockingService;
import com.ipsec.security.service.JwtTokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {
    
    @Autowired
    private SecurityBlockingService securityService;
    
    @Autowired
    private JwtTokenService jwtService;
    
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        
        String clientIp = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        
        SecurityBlockingService.LoginValidationResult result = 
            securityService.validateLogin(
                request.getUsername(),
                request.getPassword(),
                clientIp,
                userAgent
            );
        
        if (!result.success) {
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", result.message);
            return ResponseEntity.status(401).body(response);
        }
        
        String token = jwtService.generateToken(result.userId, request.getUsername(), clientIp);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Login successful");
        response.put("token", token);
        response.put("username", request.getUsername());
        response.put("expiresIn", 3600);
        
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String token) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Logged out successfully");
        
        return ResponseEntity.ok(response);
    }
    
    @GetMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(401).body("{\"valid\": false, \"message\": \"Missing Bearer token\"}");
            }
            String token = authHeader.substring(7);
            jwtService.validateToken(token);
            
            Map<String, Object> response = new HashMap<>();
            response.put("valid", true);
            response.put("username", jwtService.getUsernameFromToken(token));
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(401).body("{\"valid\": false, \"message\": \"" + e.getMessage() + "\"}");
        }
    }
    
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddr();
        }
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip;
    }
    
    public static class LoginRequest {
        private String username;
        private String password;
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
}
