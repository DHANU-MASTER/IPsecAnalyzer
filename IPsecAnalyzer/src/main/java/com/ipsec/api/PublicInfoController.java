package com.ipsec.api;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController("publicInfoController")
@RequestMapping("/api/public")
public class PublicInfoController {

    @GetMapping("/info")
    public ResponseEntity<?> getInfo() {
        return ResponseEntity.ok("IPsec Protocol Analysis API Service v1.0");
    }

    /**
     * Reports the caller's address as seen by the server, so the login page can
     * display it without calling an external service (works offline/air-gapped).
     */
    @GetMapping("/client-ip")
    public ResponseEntity<?> getClientIp(HttpServletRequest request) {
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

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ip", ip);
        return ResponseEntity.ok(body);
    }
}
