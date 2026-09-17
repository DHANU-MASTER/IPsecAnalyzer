package com.ipsec.threat;

import java.util.*;
import java.time.LocalDateTime;

/**
 * Layer-0 threat intelligence: primary source is the LIVE NVD 2.0 API
 * (see {@link NvdCveClient}, 60-minute cache). When NVD is unreachable the
 * small static catalog below is used and every response is labeled with its
 * feed basis so a reader always knows where the CVEs came from.
 */
public class ThreatIntelligenceEngine {
    
    public static class ThreatIntel {
        public String cveId;
        public String affected_cipher;
        public String severity;
        public String description;
        public LocalDateTime disclosure_date;
        public String exploit_status;
        public String mitigation;
        public double impact_score;
    }

    /**
     * Live-feed lookup for the detected cipher. Use this in the analysis
     * pipeline; {@link #fetchThreatIntel(String)} remains for callers that
     * want the offline behavior only (tests, PDF reports without network).
     */
    public static NvdCveClient.FeedResult fetchThreatIntelLive(String detectedCipher) {
        NvdCveClient.FeedResult feed = NvdCveClient.fetchForCipher(detectedCipher);
        if (feed.items == null) {
            feed.items = new ArrayList<>();
        }
        return feed;
    }

    /**
     * Offline lookup against the small static catalog. Also used by the live
     * client as the labeled fallback when NVD cannot be reached.
     */
    public static List<ThreatIntel> fetchThreatIntel(String detectedCipher) {
        List<ThreatIntel> threats = new ArrayList<>();
        if (detectedCipher == null) return threats;

        if (detectedCipher.contains("AES-128") || detectedCipher.contains("CBC")) {
            threats.add(catalogLuckyThirteen());
        }

        if (detectedCipher.contains("3DES") || detectedCipher.contains("DES")) {
            threats.add(catalogSweet32());
        }

        return threats;
    }

    /** Labeled fallback for the NVD client (same records, single entry point). */
    static List<ThreatIntel> fallbackCatalogFor(String detectedCipher) {
        return fetchThreatIntel(detectedCipher);
    }

    private static ThreatIntel catalogLuckyThirteen() {
        ThreatIntel t1 = new ThreatIntel();
        t1.cveId = "CVE-2013-0169";
        t1.affected_cipher = "AES-CBC";
        t1.severity = "High";
        t1.description = "CBC mode padding oracle vulnerability (Lucky Thirteen)";
        t1.disclosure_date = LocalDateTime.of(2013, 2, 4, 0, 0);
        t1.exploit_status = "Exploited in wild";
        t1.mitigation = "Switch to AES-GCM or ChaCha20-Poly1305";
        t1.impact_score = 7.5;
        return t1;
    }

    private static ThreatIntel catalogSweet32() {
        ThreatIntel t2 = new ThreatIntel();
        t2.cveId = "CVE-2016-2183";
        t2.affected_cipher = "3DES";
        t2.severity = "Critical";
        t2.description = "Sweet32: Birthday attacks on 64-bit block ciphers in TLS/IPsec";
        t2.disclosure_date = LocalDateTime.of(2016, 8, 24, 0, 0);
        t2.exploit_status = "Actively exploited";
        t2.mitigation = "Disable 3DES immediately, use AES-256";
        t2.impact_score = 9.8;
        return t2;
    }
    
    public static String generateContextualThreatAnalysis(
            List<ThreatIntel> intels,
            double currentRiskScore) {
        
        StringBuilder analysis = new StringBuilder();
        analysis.append("🚨 CONTEXTUAL THREAT ANALYSIS\n");
        analysis.append("==============================\n\n");
        
        if (intels == null || intels.isEmpty()) {
            analysis.append("✓ No known CVEs detected for your cipher suite\n");
            return analysis.toString();
        }
        
        double aggregatedRisk = currentRiskScore;
        for (ThreatIntel intel : intels) {
            aggregatedRisk += intel.impact_score;
            analysis.append(String.format("⚠️  %s: %s\n", intel.cveId, intel.description));
            analysis.append(String.format("   Severity: %s | Exploit Status: %s\n",
                intel.severity, intel.exploit_status));
            analysis.append(String.format("   Mitigation: %s\n\n", intel.mitigation));
        }
        
        analysis.append(String.format("AGGREGATED RISK SCORE: %.1f/100\n", 
            Math.min(aggregatedRisk, 100.0)));
        analysis.append("Priority: IMMEDIATE ACTION REQUIRED\n");
        
        return analysis.toString();
    }
}
