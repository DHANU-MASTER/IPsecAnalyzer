package com.ipsec.scoring;

import java.util.*;

public class SecurityScorer {
    
    public static class SecurityAssessment {
        public double overallRiskScore; // 0-100, higher = riskier
        public String riskLevel;        // "Critical", "High", "Medium", "Low"
        public List<String> vulnerabilities;
        public List<String> recommendations;
        public Map<String, Double> componentScores;
        
        @Override
        public String toString() {
            return String.format("Risk Score: %.1f (%s)\nVulns: %s\nRecs: %s",
                overallRiskScore, riskLevel, vulnerabilities, recommendations);
        }
    }
    
    public static SecurityAssessment scoreIPsecConfig(
            String inferredCipher,
            String inferredTunnelMode,
            int dhGroup,
            boolean pfsEnabled,
            long keyLifetime) {
        
        SecurityAssessment assessment = new SecurityAssessment();
        assessment.vulnerabilities = new ArrayList<>();
        assessment.recommendations = new ArrayList<>();
        assessment.componentScores = new HashMap<>();
        
        double totalScore = 0;
        int factors = 0;
        
        // 1. Cipher strength scoring
        double cipherScore = scoreCipher(inferredCipher);
        assessment.componentScores.put("Cipher", cipherScore);
        totalScore += cipherScore;
        factors++;
        
        if (cipherScore > 60) {
            assessment.vulnerabilities.add("Weak or outdated cipher: " + inferredCipher);
            assessment.recommendations.add("Upgrade to AES-256-GCM or ChaCha20");
        }
        
        // 2. DH Group strength
        double dhScore = scoreDHGroup(dhGroup);
        assessment.componentScores.put("DH Group", dhScore);
        totalScore += dhScore;
        factors++;
        
        if (dhScore > 50) {
            assessment.vulnerabilities.add("Weak DH group: " + dhGroup);
            assessment.recommendations.add("Use DH Group 14+ or ECP groups");
        }
        
        // 3. Perfect Forward Secrecy
        double pfsScore = pfsEnabled ? 0 : 50;
        assessment.componentScores.put("PFS", pfsScore);
        totalScore += pfsScore;
        factors++;
        
        if (!pfsEnabled) {
            assessment.vulnerabilities.add("Perfect Forward Secrecy (PFS) disabled");
            assessment.recommendations.add("Enable PFS for long-lived sessions");
        }
        
        // 4. Key lifetime check
        double lifetimeScore = scoreKeyLifetime(keyLifetime);
        assessment.componentScores.put("Key Lifetime", lifetimeScore);
        totalScore += lifetimeScore;
        factors++;
        
        if (keyLifetime > 86400) {
            assessment.vulnerabilities.add("Excessive key lifetime: " + keyLifetime + "s");
            assessment.recommendations.add("Reduce key lifetime to 3600-14400s");
        }
        
        // 5. Tunnel vs Transport mode
        double modeScore = "Tunnel".equalsIgnoreCase(inferredTunnelMode) ? 0 : 30;
        assessment.componentScores.put("Mode", modeScore);
        totalScore += modeScore;
        factors++;
        
        if (modeScore > 0) {
            assessment.vulnerabilities.add("Transport mode exposes IP headers");
            assessment.recommendations.add("Use Tunnel mode for better IP header protection");
        }
        
        assessment.overallRiskScore = totalScore / factors;
        
        if (assessment.overallRiskScore < 20) {
            assessment.riskLevel = "Low";
        } else if (assessment.overallRiskScore < 40) {
            assessment.riskLevel = "Medium";
        } else if (assessment.overallRiskScore < 70) {
            assessment.riskLevel = "High";
        } else {
            assessment.riskLevel = "Critical";
        }
        
        return assessment;
    }
    
    private static double scoreCipher(String cipher) {
        if (cipher == null) return 50;
        if (cipher.contains("AES-256-GCM")) return 5;
        if (cipher.contains("AES-256")) return 15;
        if (cipher.contains("ChaCha20")) return 10;
        if (cipher.contains("AES-128-GCM")) return 25;
        if (cipher.contains("AES-128")) return 35;
        if (cipher.contains("3DES")) return 80;
        if (cipher.contains("DES")) return 95;
        return 50;
    }
    
    private static double scoreDHGroup(int dhGroup) {
        if (dhGroup >= 20) return 0;
        if (dhGroup >= 14) return 10;
        if (dhGroup >= 5) return 40;
        return 80;
    }
    
    private static double scoreKeyLifetime(long seconds) {
        if (seconds <= 3600) return 0;
        if (seconds <= 14400) return 10;
        if (seconds <= 86400) return 40;
        if (seconds <= 604800) return 70;
        return 95;
    }
}
