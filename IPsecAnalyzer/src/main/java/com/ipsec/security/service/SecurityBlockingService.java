package com.ipsec.security.service;

import com.ipsec.security.entity.User;
import com.ipsec.security.entity.LoginAttempt;
import com.ipsec.security.repository.UserRepository;
import com.ipsec.security.repository.LoginAttemptRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class SecurityBlockingService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private LoginAttemptRepository loginAttemptRepository;
    
    @Autowired(required = false)
    private BCryptPasswordEncoder passwordEncoder;
    
    private static final int MAX_FAILED_ATTEMPTS = 4;
    private static final int LOCKOUT_DURATION_MINUTES = 30;

    // Per-IP brute-force throttle (prevents account-lockout DoS attacks)
    private static final int IP_MAX_ATTEMPTS_PER_WINDOW = 10;
    private static final int IP_WINDOW_MINUTES = 15;
    
    public LoginValidationResult validateLogin(String username, String password, 
                                               String clientIp, String userAgent) {
        
        Optional<User> userOpt = userRepository.findByUsername(username);
        
        if (!userOpt.isPresent()) {
            return new LoginValidationResult(false, "User not found");
        }
        
        // device_fingerprint is NOT NULL in the schema, so it is computed up front
        // and used by every audit write below (including the throttled branch).
        String deviceFingerprint = generateDeviceFingerprint(userAgent, clientIp);
        
        // 0. Per-IP throttle: too many failures from one IP blocks that IP
        //    (not the account), so brute force is stopped without letting an
        //    attacker lock legitimate users out of their account.
        if (isIpThrottled(clientIp)) {
            logFailedAttempt(username, clientIp, deviceFingerprint,
                "IP throttled - too many failed attempts");
            return new LoginValidationResult(false,
                "Too many failed attempts from this network. Try again in "
                    + IP_WINDOW_MINUTES + " minutes.");
        }
        
        User user = userOpt.get();
        
        // 1. Check Account Lockout
        if (Boolean.TRUE.equals(user.getAccountLocked())) {
            if (user.getLockedUntil() != null && LocalDateTime.now().isBefore(user.getLockedUntil())) {
                logFailedAttempt(username, clientIp, deviceFingerprint, 
                    "Account locked - max attempts exceeded");
                return new LoginValidationResult(false, 
                    "Account locked. Try again after " + user.getLockedUntil());
            } else {
                user.setAccountLocked(false);
                user.setFailedAttempts(0);
                userRepository.save(user);
            }
        }
        
        // 2. Check Password
        if (!verifyPassword(password, user.getPasswordHash())) {
            user.setFailedAttempts((user.getFailedAttempts() != null ? user.getFailedAttempts() : 0) + 1);
            
            if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
                user.setAccountLocked(true);
                user.setLockedUntil(LocalDateTime.now().plusMinutes(LOCKOUT_DURATION_MINUTES));
                userRepository.save(user);
                
                logFailedAttempt(username, clientIp, deviceFingerprint, "Wrong password - locked");
                
                return new LoginValidationResult(false, 
                    "❌ Wrong password. Account locked after 4 attempts.");
            }
            
            userRepository.save(user);
            logFailedAttempt(username, clientIp, deviceFingerprint, 
                String.format("Wrong password (Attempt %d/4)", user.getFailedAttempts()));
            
            return new LoginValidationResult(false, 
                "Wrong password. Attempts remaining: " + (MAX_FAILED_ATTEMPTS - user.getFailedAttempts()));
        }
        
        // 3. Password Verified - Bind / Update Whitelisted IP for Admin User
        if (clientIp != null && !clientIp.isEmpty()) {
            user.setWhitelistedIp(clientIp);
        }
        
        user.setFailedAttempts(0);
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);
        
        logSuccessfulLogin(username, clientIp, deviceFingerprint);
        
        return new LoginValidationResult(true, "Login successful", user.getId());
    }
    
    private String generateDeviceFingerprint(String userAgent, String clientIp) {
        String combined = (userAgent != null ? userAgent : "") + "|" + (clientIp != null ? clientIp : "");
        String fingerprint = Integer.toHexString(combined.hashCode());
        // Never hand a null to the NOT NULL device_fingerprint column.
        return fingerprint.isEmpty() ? "unknown" : fingerprint;
    }
    
    private boolean verifyPassword(String rawPassword, String hashedPassword) {
        if (passwordEncoder != null) {
            try {
                if (passwordEncoder.matches(rawPassword, hashedPassword)) {
                    return true;
                }
            } catch (Exception ignored) {
            }
        }
        try {
            if (org.springframework.security.crypto.bcrypt.BCrypt.checkpw(rawPassword, hashedPassword)) {
                return true;
            }
        } catch (Exception ignored) {
        }
        return false;
    }
    
    private boolean isIpThrottled(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        return countRecentFailuresForIp(ip) >= IP_MAX_ATTEMPTS_PER_WINDOW;
    }
    
    private int countRecentFailuresForIp(String ip) {
        try {
            LocalDateTime since = LocalDateTime.now().minusMinutes(IP_WINDOW_MINUTES);
            long count = loginAttemptRepository.countFailedAttemptsSince(ip, since);
            return (int) Math.min(count, Integer.MAX_VALUE);
        } catch (Exception e) {
            return 0;
        }
    }
    
    private void logFailedAttempt(String username, String ip, String fingerprint, String reason) {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUsername(username != null ? username : "unknown");
        attempt.setIpAddress(ip != null ? ip : "unknown");
        attempt.setDeviceFingerprint(fingerprint != null ? fingerprint : "unknown");
        attempt.setSuccess(false);
        attempt.setFailureReason(reason);
        loginAttemptRepository.save(attempt);
    }
    
    private void logSuccessfulLogin(String username, String ip, String fingerprint) {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUsername(username != null ? username : "unknown");
        attempt.setIpAddress(ip != null ? ip : "unknown");
        attempt.setDeviceFingerprint(fingerprint != null ? fingerprint : "unknown");
        attempt.setSuccess(true);
        loginAttemptRepository.save(attempt);
    }
    
    public static class LoginValidationResult {
        public boolean success;
        public String message;
        public Long userId;
        
        public LoginValidationResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
        
        public LoginValidationResult(boolean success, String message, Long userId) {
            this.success = success;
            this.message = message;
            this.userId = userId;
        }
    }
}
