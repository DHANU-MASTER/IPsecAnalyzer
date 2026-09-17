package com.ipsec.scoring;

import java.util.*;

public class ThreatMatrix {
    
    public static class Threat {
        public String name;
        public String severity;    // "Critical", "High", "Medium", "Low"
        public String likelihood;  // "High", "Medium", "Low"
        public String mitigation;
        
        public int getRiskScore() {
            int severityVal = "Critical".equals(severity) ? 4 : 
                             "High".equals(severity) ? 3 : 
                             "Medium".equals(severity) ? 2 : 1;
            int likelihoodVal = "High".equals(likelihood) ? 3 : 
                               "Medium".equals(likelihood) ? 2 : 1;
            return severityVal * likelihoodVal;
        }
    }
    
    public static List<Threat> generateThreatMatrix(SecurityScorer.SecurityAssessment assessment) {
        List<Threat> threats = new ArrayList<>();
        
        if (assessment == null || assessment.vulnerabilities == null) {
            return threats;
        }
        
        for (String vuln : assessment.vulnerabilities) {
            Threat threat = new Threat();
            threat.name = vuln;
            
            if (vuln.contains("weak") || vuln.contains("DES")) {
                threat.severity = "Critical";
                threat.likelihood = "High";
                threat.mitigation = "Upgrade to strong cryptography immediately";
            } else if (vuln.contains("PFS")) {
                threat.severity = "High";
                threat.likelihood = "Medium";
                threat.mitigation = "Enable PFS in IKE configuration";
            } else if (vuln.contains("Transport")) {
                threat.severity = "Medium";
                threat.likelihood = "Medium";
                threat.mitigation = "Switch to Tunnel mode";
            } else if (vuln.contains("Key Lifetime")) {
                threat.severity = "High";
                threat.likelihood = "Low";
                threat.mitigation = "Reduce key refresh interval";
            } else {
                threat.severity = "Medium";
                threat.likelihood = "Medium";
                threat.mitigation = "Review configuration";
            }
            
            threats.add(threat);
        }
        
        threats.sort((a, b) -> Integer.compare(b.getRiskScore(), a.getRiskScore()));
        
        return threats;
    }
}
