package com.ipsec.pqc;

import java.util.*;

public class PQCReadinessAssessor {
    
    public static class PQCAssessment {
        public String current_cipher;
        public boolean is_pqc_resistant;
        public String recommendation;
        public String migration_timeline;
        public List<String> pqc_alternatives;
        public int readiness_score; // 0-100
        public String nist_status;
        public String expected_sunset_date;
    }
    
    public static PQCAssessment assessPQCReadiness(String detectedCipher) {
        PQCAssessment assessment = new PQCAssessment();
        assessment.current_cipher = detectedCipher != null ? detectedCipher : "Unknown";
        assessment.pqc_alternatives = new ArrayList<>();
        
        if (assessment.current_cipher.contains("AES-256-GCM") || assessment.current_cipher.contains("AES-256")) {
            assessment.is_pqc_resistant = false;
            assessment.readiness_score = 65;
            assessment.recommendation = "AES-256 is safe for symmetric encryption even post-quantum. " +
                                       "Focus on key exchange: use RFC 7748 (Curve25519) + potential PQC KEM";
            assessment.migration_timeline = "2025-2026: Hybrid classical-PQC KEMs";
            assessment.pqc_alternatives.add("ML-KEM (Kyber) - NIST FIPS 203 (2024)");
            assessment.pqc_alternatives.add("ML-DSA (Dilithium) - NIST FIPS 204 (2024)");
            assessment.pqc_alternatives.add("Hybrid: X25519 + ML-KEM-768");
            assessment.nist_status = "FIPS 203/204 Approved (2024)";
            assessment.expected_sunset_date = "2035+ (safe beyond quantum threat)";
        } 
        else if (assessment.current_cipher.contains("AES-128")) {
            assessment.is_pqc_resistant = false;
            assessment.readiness_score = 45;
            assessment.recommendation = "AES-128 considered quantum-unsafe by NIST post-2030. " +
                                       "Upgrade to AES-256 immediately for long-term secrets";
            assessment.migration_timeline = "URGENT: 2024-2025";
            assessment.pqc_alternatives.add("AES-256-GCM (interim, until ML-KEM mature)");
            assessment.pqc_alternatives.add("ML-KEM-768 for key exchange");
            assessment.nist_status = "Recommendation: Upgrade NOW";
            assessment.expected_sunset_date = "2030 (NIST guideline)";
        }
        else {
            assessment.is_pqc_resistant = false;
            assessment.readiness_score = 15;
            assessment.recommendation = "Legacy cipher detected. CRITICAL: Disable immediately. " +
                                       "Not PQC-safe and vulnerable to classical attacks.";
            assessment.migration_timeline = "CRITICAL: Immediate";
            assessment.pqc_alternatives.add("AES-256-GCM ONLY");
            assessment.nist_status = "DEPRECATED";
            assessment.expected_sunset_date = "2020 (passed)";
        }
        
        return assessment;
    }
    
    public static String generatePQCRoadmap(PQCAssessment assessment) {
        StringBuilder roadmap = new StringBuilder();
        
        roadmap.append("📊 POST-QUANTUM CRYPTOGRAPHY (PQC) READINESS REPORT\n");
        roadmap.append("==================================================\n\n");
        
        roadmap.append(String.format("Current Cipher: %s\n", assessment.current_cipher));
        roadmap.append(String.format("PQC-Resistant: %s\n", assessment.is_pqc_resistant ? "YES ✓" : "NO ✗"));
        roadmap.append(String.format("Readiness Score: %d/100\n\n", assessment.readiness_score));
        
        roadmap.append("TIMELINE & MILESTONES:\n");
        roadmap.append("├─ 2024: NIST finalizes ML-KEM, ML-DSA (FIPS 203/204)\n");
        roadmap.append("├─ 2025: Organizations begin hybrid (classical + PQC) deployment\n");
        roadmap.append("├─ 2026-2030: Full migration to PQC-resistant algorithms\n");
        roadmap.append("└─ 2030+: Classical-only crypto considered obsolete\n\n");
        
        roadmap.append("YOUR MIGRATION STRATEGY:\n");
        roadmap.append(String.format("Phase 1 (Now): %s\n", assessment.recommendation));
        roadmap.append("Phase 2 (2025): Deploy hybrid ML-KEM + X25519 key exchange\n");
        roadmap.append("Phase 3 (2027): Transition to pure PQC-resistant algorithms\n\n");
        
        roadmap.append("RECOMMENDED PQC ALGORITHMS (NIST Approved):\n");
        for (String alt : assessment.pqc_alternatives) {
            roadmap.append(String.format("  ✓ %s\n", alt));
        }
        
        return roadmap.toString();
    }
}
