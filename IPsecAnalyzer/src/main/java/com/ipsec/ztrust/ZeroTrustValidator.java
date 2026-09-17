package com.ipsec.ztrust;

import java.util.*;

public class ZeroTrustValidator {
    
    public static class ZeroTrustAssessment {
        public boolean ztrust_ready;
        public double ztrust_score; // 0-100
        public List<String> ztrust_gaps;
        public List<String> ztrust_recommendations;
        public String implementation_roadmap;
    }
    
    public static ZeroTrustAssessment assessZeroTrustReadiness(
            String tunnelMode,
            String cipher,
            boolean pfsEnabled,
            boolean mfa_enforced) {
        
        ZeroTrustAssessment assessment = new ZeroTrustAssessment();
        assessment.ztrust_gaps = new ArrayList<>();
        assessment.ztrust_recommendations = new ArrayList<>();
        
        double score = 0;
        
        if (cipher != null && cipher.contains("AES-256-GCM")) {
            score += 25;
        } else if (cipher != null && cipher.contains("AES-256")) {
            score += 20;
        } else if (cipher != null && cipher.contains("AES-128")) {
            score += 10;
            assessment.ztrust_gaps.add("Weak cipher for ZT: AES-128 insufficient for long-term secrets");
            assessment.ztrust_recommendations.add("Upgrade to AES-256-GCM");
        } else {
            assessment.ztrust_gaps.add("Non-compliant cipher for Zero-Trust architecture");
            assessment.ztrust_recommendations.add("Upgrade to AES-256-GCM");
        }
        
        if (pfsEnabled) {
            score += 25;
        } else {
            assessment.ztrust_gaps.add("PFS disabled: Violates Zero-Trust principle of least privilege");
            assessment.ztrust_recommendations.add("Enable PFS for ephemeral key agreement");
        }
        
        if ("Tunnel".equalsIgnoreCase(tunnelMode)) {
            score += 20;
        } else {
            score += 5;
            assessment.ztrust_gaps.add("Transport mode: Exposes IP headers (violates ZT principle)");
            assessment.ztrust_recommendations.add("Migrate to Tunnel mode");
        }
        
        if (mfa_enforced) {
            score += 20;
        } else {
            assessment.ztrust_gaps.add("No MFA: Zero-Trust requires multi-factor identity verification");
            assessment.ztrust_recommendations.add("Implement certificate-based auth + MFA");
        }
        
        assessment.ztrust_gaps.add("IPsec lacks continuous user telemetry monitoring");
        assessment.ztrust_recommendations.add("Add application-level telemetry + EDR integration");
        score += 10;
        
        assessment.ztrust_score = score;
        assessment.ztrust_ready = score >= 70;
        
        StringBuilder roadmap = new StringBuilder();
        roadmap.append("ZERO-TRUST MIGRATION ROADMAP:\n");
        roadmap.append("Phase 1 (Now): Fix encryption + enable PFS\n");
        roadmap.append("Phase 2 (3mo): Deploy MFA for tunnel access\n");
        roadmap.append("Phase 3 (6mo): Implement continuous verification\n");
        roadmap.append("Phase 4 (1yr): Full Zero-Trust Network Access (ZTNA) platform\n");
        
        assessment.implementation_roadmap = roadmap.toString();
        
        return assessment;
    }
}
