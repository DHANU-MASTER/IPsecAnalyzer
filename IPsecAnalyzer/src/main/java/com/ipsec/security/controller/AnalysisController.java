package com.ipsec.security.controller;

import com.ipsec.api.AnalysisPipeline;
import com.ipsec.api.PdfReportService;
import com.ipsec.features.FeatureExtractor;
import com.ipsec.ml.Predictor;
import com.ipsec.scoring.SecurityScorer;
import com.ipsec.scoring.ThreatMatrix;
import com.ipsec.security.entity.AnalysisHistory;
import com.ipsec.security.repository.AnalysisHistoryRepository;
import com.ipsec.security.service.JwtTokenService;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/analyze")
public class AnalysisController {

    @Autowired(required = false)
    private AnalysisHistoryRepository analysisHistoryRepository;

    @Autowired
    private JwtTokenService jwtService;

    @Autowired
    private AnalysisPipeline analysisPipeline;

    /**
     * Analyses an uploaded capture. The configuration parameters below cannot be
     * observed in encrypted traffic, so they may be supplied explicitly; when
     * omitted the documented defaults are used and reported as assumptions.
     */
    @PostMapping(value = "/pcap", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> analyzePcap(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "dhGroup", required = false) Integer dhGroup,
            @RequestParam(value = "pfs", required = false) Boolean pfs,
            @RequestParam(value = "keyLifetime", required = false) Long keyLifetime,
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            HttpServletRequest httpRequest) {

        try {
            if (file == null || file.getOriginalFilename() == null || file.getOriginalFilename().isEmpty()) {
                Map<String, Object> err = new HashMap<>();
                err.put("error", "The uploaded .pcap file is empty. Please select a valid .pcap file.");
                return ResponseEntity.badRequest().body(err);
            }

            String token = (authHeader != null && authHeader.startsWith("Bearer "))
                ? authHeader.substring(7) : null;
            Long userId = token != null ? jwtService.getUserIdFromToken(token) : 1L;
            String clientIp = getClientIp(httpRequest);

            Map<String, Object> response = analysisPipeline.run(
                file, userId, clientIp, dhGroup, pfs, keyLifetime, null);

            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(err);
        } catch (Exception e) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", e.getMessage() != null ? e.getMessage() : "Analysis failed");
            return ResponseEntity.badRequest().body(err);
        }
    }

    /**
     * Snapshot of the last analysis, posted back by the dashboard to render
     * a downloadable PDF. Field names match the serialized analysis response,
     * so Jackson binds them back onto the real types.
     */
    public static class ReportRequest {
        public SecurityScorer.SecurityAssessment assessment;
        public FeatureExtractor.PacketFeatures features;
        public Predictor.PredictionResult prediction;
        public List<ThreatMatrix.Threat> threats;
    }

    /** Real PDF rendering of the executive summary. */
    @PostMapping(value = "/reports/executive-pdf", produces = "application/pdf")
    public ResponseEntity<byte[]> executivePdf(@RequestBody ReportRequest request) {
        if (request == null || request.assessment == null) {
            return ResponseEntity.badRequest().build();
        }
        byte[] pdf = PdfReportService.executiveReport(
            request.assessment,
            request.threats != null ? request.threats : Collections.emptyList());
        return pdfResponse(pdf, "ipsec_executive_report");
    }

    /** Real PDF rendering of the technical report. */
    @PostMapping(value = "/reports/technical-pdf", produces = "application/pdf")
    public ResponseEntity<byte[]> technicalPdf(@RequestBody ReportRequest request) {
        if (request == null || request.assessment == null || request.features == null
                || request.prediction == null) {
            return ResponseEntity.badRequest().build();
        }
        byte[] pdf = PdfReportService.technicalReport(
            request.features,
            request.prediction,
            request.assessment,
            request.threats != null ? request.threats : Collections.emptyList());
        return pdfResponse(pdf, "ipsec_technical_report");
    }

    private static ResponseEntity<byte[]> pdfResponse(byte[] pdf, String baseName) {
        return ResponseEntity.ok()
            .header("Content-Disposition",
                "attachment; filename=" + baseName + "_" + System.currentTimeMillis() + ".pdf")
            .contentType(MediaType.APPLICATION_PDF)
            .body(pdf);
    }

    @GetMapping(value = "/history", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getAnalysisHistory(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                Map<String, Object> err = new HashMap<>();
                err.put("error", "Missing or invalid Authorization header");
                return ResponseEntity.status(401).body(err);
            }
            String token = authHeader.substring(7);
            Long userId = jwtService.getUserIdFromToken(token);

            if (analysisHistoryRepository != null) {
                List<AnalysisHistory> history = analysisHistoryRepository.findByUserId(userId);
                return ResponseEntity.ok(history);
            }
            return ResponseEntity.ok(Collections.emptyList());

        } catch (Exception e) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", e.getMessage() != null ? e.getMessage() : "Failed to fetch history");
            return ResponseEntity.badRequest().body(err);
        }
    }

    static String getClientIp(HttpServletRequest request) {
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
}
