package com.ipsec.api;

import com.ipsec.security.service.JwtTokenService;
import io.jsonwebtoken.JwtException;
import jakarta.annotation.PreDestroy;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Streaming variant of the analysis endpoint. The uploaded capture is stored
 * synchronously (Spring removes multipart temp files when the request ends),
 * then analysed in a bounded worker pool while progress events are published
 * to {@code /topic/analysis/{username}} and the final payload to
 * {@code /topic/analysis/{username}/result}.
 */
@Controller
public class AnalysisWebSocketController {

    @Autowired(required = false)
    private SimpMessagingTemplate messagingTemplate;

    @Autowired
    private AnalysisPipeline analysisPipeline;

    @Autowired
    private JwtTokenService jwtService;

    /** Bounded pool: a raw new Thread() per request could exhaust threads under load. */
    private final ExecutorService executor = Executors.newFixedThreadPool(4, runnable -> {
        Thread thread = new Thread(runnable, "analysis-stream");
        thread.setDaemon(true);
        return thread;
    });

    @PostMapping(value = "/api/analyze/pcap-streaming", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<?> analyzePcapStreaming(
            @RequestParam("file") MultipartFile file,
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            HttpServletRequest request) {

        if (file == null || file.isEmpty() || file.getOriginalFilename() == null
                || file.getOriginalFilename().isEmpty()) {
            return ResponseEntity.badRequest().body(error("Please select a non-empty .pcap file."));
        }

        String token = (authHeader != null && authHeader.startsWith("Bearer "))
            ? authHeader.substring(7) : null;
        if (token == null) {
            return ResponseEntity.status(401).body(error("Missing or invalid Authorization header"));
        }

        final String username;
        final Long userId;
        try {
            username = jwtService.getUsernameFromToken(token);
            userId = jwtService.getUserIdFromToken(token);
        } catch (JwtException e) {
            return ResponseEntity.status(401).body(error("Invalid or expired token"));
        }

        final File storedFile;
        try {
            storedFile = analysisPipeline.store(file);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(error("Could not store upload: " + e.getMessage()));
        }

        final String originalFilename = file.getOriginalFilename();
        final String clientIp = getClientIp(request);
        final String progressTopic = "/topic/analysis/" + username;

        executor.submit(() -> {
            try {
                Map<String, Object> result = analysisPipeline.run(
                    storedFile, originalFilename, userId, clientIp,
                    null, null, null, true,
                    (percent, status) -> publish(progressTopic, progress(percent, status))
                );
                publish(progressTopic + "/result", result);
            } catch (Exception e) {
                publish(progressTopic, progressError(
                    e.getMessage() != null ? e.getMessage() : "Analysis failed"));
            }
        });

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "streaming_started");
        body.put("topic", progressTopic);
        body.put("resultTopic", progressTopic + "/result");
        return ResponseEntity.accepted().body(body);
    }

    private void publish(String destination, Object payload) {
        if (messagingTemplate == null) {
            return;
        }
        try {
            messagingTemplate.convertAndSend(destination, payload);
        } catch (Exception e) {
            System.err.println("[WARN] Could not publish to " + destination + ": " + e.getMessage());
        }
    }

    private Map<String, Object> progress(int percent, String status) {
        Map<String, Object> message = new LinkedHashMap<>();
        message.put("type", "progress");
        message.put("percent", percent);
        message.put("status", status);
        message.put("timestamp", System.currentTimeMillis());
        return message;
    }

    private Map<String, Object> progressError(String message) {
        Map<String, Object> payload = progress(100, "failed");
        payload.put("type", "error");
        payload.put("error", message);
        return payload;
    }

    private Map<String, Object> error(String message) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("error", message);
        return payload;
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

    @PreDestroy
    public void shutdown() {
        executor.shutdownNow();
    }
}
