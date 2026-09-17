package com.ipsec.api;

import com.ipsec.features.FeatureExtractor;
import com.ipsec.ml.Predictor;
import com.ipsec.scoring.SecurityScorer;
import com.ipsec.scoring.ThreatMatrix;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public class ReportService {
    
    public static String generateExecutiveReport(
            SecurityScorer.SecurityAssessment assessment,
            List<ThreatMatrix.Threat> threats) {
        
        StringBuilder report = new StringBuilder();
        
        report.append("=== EXECUTIVE SUMMARY ===\n\n");
        report.append(String.format("Report Generated: %s\n", LocalDateTime.now()));
        report.append(String.format("Overall Risk Score: %.1f/100 (%s)\n\n", 
            assessment.overallRiskScore, assessment.riskLevel));
        
        report.append("KEY FINDINGS:\n");
        for (String vuln : assessment.vulnerabilities) {
            report.append("  • ").append(vuln).append("\n");
        }
        
        report.append("\nRECOMMENDATIONS:\n");
        for (String rec : assessment.recommendations) {
            report.append("  → ").append(rec).append("\n");
        }
        
        return report.toString();
    }
    
    public static String generateTechnicalReport(
            FeatureExtractor.PacketFeatures features,
            Predictor.PredictionResult prediction,
            SecurityScorer.SecurityAssessment assessment,
            List<ThreatMatrix.Threat> threats) {
        
        StringBuilder report = new StringBuilder();
        
        report.append("=== TECHNICAL ANALYSIS REPORT ===\n\n");
        
        report.append("CAPTURED TRAFFIC CHARACTERISTICS:\n");
        report.append(String.format("  Avg Packet Size: %.2f bytes\n", features.avgPacketSize));
        report.append(String.format("  Std Dev Packet Size: %.2f bytes\n", features.stdPacketSize));
        report.append(String.format("  IKE Packets: %d\n", features.ikeNegotiationCount));
        report.append(String.format("  ESP Packets: %d\n\n", features.espPacketCount));
        
        report.append("AI CLASSIFICATION RESULTS:\n");
        report.append(String.format("  Predicted Cipher: %s (%.1f%% confidence)\n", 
            prediction.predictedCipher, prediction.cipherConfidence * 100));
        report.append(String.format("  Predicted Mode: %s (%.1f%% confidence)\n\n", 
            prediction.predictedTunnelMode, prediction.tunnelConfidence * 100));
        
        report.append("SECURITY ASSESSMENT:\n");
        for (Map.Entry<String, Double> entry : assessment.componentScores.entrySet()) {
            report.append(String.format("  %s: %.1f\n", entry.getKey(), entry.getValue()));
        }
        
        report.append("\nTHREAT MATRIX:\n");
        for (ThreatMatrix.Threat threat : threats) {
            report.append(String.format("  [%s] %s (Likelihood: %s)\n", 
                threat.severity, threat.name, threat.likelihood));
            report.append(String.format("    Mitigation: %s\n", threat.mitigation));
        }
        
        return report.toString();
    }
}
