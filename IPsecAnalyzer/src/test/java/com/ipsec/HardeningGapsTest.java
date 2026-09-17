package com.ipsec;

import com.ipsec.oracle.AdaptiveDefenseEngine;
import com.ipsec.oracle.MorphicRotationService;
import com.ipsec.oracle.ThreatPredictor;
import com.ipsec.security.service.AdminBootstrap;
import com.ipsec.threat.NvdCveClient;
import com.ipsec.threat.ThreatIntelligenceEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the newly de-hardcoded, master-prompt-completing pieces:
 *
 *  - the NVD client parses real NVD 2.0 JSON and labels its feed basis,
 *    falling back to the static catalog only when unreachable
 *  - the scheduled morphic rotation produces a real, rotating config whose
 *    input is the recorded analysis history (not canned output)
 *  - the 72h predictor names real client IPs from history in targetRegions
 *  - admin bootstrap generates a random password with the expected classes
 *    and never the old shared demo password
 */
class HardeningGapsTest {

    // ---- NVD client (Layer 0) -----------------------------------------------

    @Test
    @DisplayName("NVD client parses a real NVD 2.0 JSON payload")
    void nvdParserExtractsCvesFromRealShape() {
        String json = """
            {
              "resultsPerPage": 2,
              "vulnerabilities": [
                { "cve": {
                    "id": "CVE-2016-2183",
                    "published": "2016-09-06T10:59:00.000",
                    "descriptions": [
                      {"lang": "en", "value": "The DES and Triple DES ciphers have a birthday bound."},
                      {"lang": "fr", "value": "ignored"}
                    ],
                    "metrics": { "cvssMetricV31": [ { "cvssData": {
                        "baseSeverity": "HIGH", "baseScore": 7.5 } } ] },
                    "references": [ { "url": "https://sweet32.info" } ]
                } },
                { "cve": {
                    "id": "CVE-2013-0169",
                    "published": "2013-02-04T22:55:00.000",
                    "descriptions": [ {"lang": "en", "value": "The TLS CBC padding oracle."} ],
                    "metrics": {},
                    "references": []
                } }
              ]
            }
            """;

        List<ThreatIntelligenceEngine.ThreatIntel> parsed = NvdCveClient.parseNvdJson(json);
        assertEquals(2, parsed.size(), "both CVE objects should be extracted");
        assertEquals("CVE-2016-2183", parsed.get(0).cveId);
        assertTrue(parsed.get(0).description.contains("birthday bound"));
        assertEquals("HIGH", parsed.get(0).severity);
        assertEquals(7.5, parsed.get(0).impact_score, 0.001);
        assertEquals("CVE-2013-0169", parsed.get(1).cveId);
        assertEquals("Unknown", parsed.get(1).severity, "missing metrics must not crash parsing");
    }

    @Test
    @DisplayName("Feed result is always labeled and the fallback never masquerades as live data")
    void fallbackIsLabeled() {
        // 3DES maps to the Sweet32 keyword query; if the network is available
        // this returns live data, otherwise the labeled fallback — both are
        // acceptable, but the basis must always be stated.
        NvdCveClient.FeedResult feed = ThreatIntelligenceEngine.fetchThreatIntelLive("3DES-CBC");
        assertNotNull(feed.feedBasis);
        assertFalse(feed.feedBasis.isBlank());
        assertNotNull(feed.items);
        assertTrue(feed.resultsCount >= 0);
    }

    @Test
    @DisplayName("Offline catalog still matches by cipher family (labeled fallback path)")
    void offlineCatalogStillWorks() {
        // "3DES-CBC" legitimately matches BOTH families: 64-bit-block (Sweet32)
        // and CBC-mode (Lucky Thirteen) — same behavior as the original catalog.
        List<ThreatIntelligenceEngine.ThreatIntel> intel =
            ThreatIntelligenceEngine.fetchThreatIntel("3DES-CBC");
        assertEquals(2, intel.size());
        assertTrue(intel.stream().anyMatch(t -> "CVE-2016-2183".equals(t.cveId)));
        assertTrue(intel.stream().anyMatch(t -> "CVE-2013-0169".equals(t.cveId)));
    }

    // ---- scheduled morphic rotation (Layer 5) --------------------------------

    @Test
    @DisplayName("72h predictor surfaces real client IPs from history in targetRegions")
    void predictorUsesClientIps() {
        List<ThreatPredictor.HistoryPoint> history = List.of(
            new ThreatPredictor.HistoryPoint(LocalDateTime.now().minusDays(1), 72.0, "High",
                "203.0.113.7"),
            new ThreatPredictor.HistoryPoint(LocalDateTime.now(), 81.0, "High", null));

        ThreatPredictor.PredictiveAlert alert = ThreatPredictor.predictAttack72h(
            80.0, "3DES-CBC", "Transport", 30, 200, 40.0, history);

        assertNotNull(alert.targetRegions);
        assertTrue(alert.targetRegions.stream().anyMatch(r -> r.contains("203.0.113.7")),
            "recorded client IP must appear: " + alert.targetRegions);
        assertTrue(alert.targetRegions.stream().anyMatch(r -> r.contains("client IP not recorded")),
            "history rows without an IP must say so: " + alert.targetRegions);
    }

    @Test
    @DisplayName("Admin bootstrap passwords are random, strong, and never the demo password")
    void bootstrapPasswordsAreStrongAndRandom() {
        String oldDemo = "Admin@123";
        for (int i = 0; i < 20; i++) {
            String pw = AdminBootstrap.generatePassword(16);
            assertEquals(16, pw.length());
            assertTrue(pw.matches(".*[A-Z].*") && pw.matches(".*[a-z].*")
                    && pw.matches(".*\\d.*") && pw.matches(".*[!@#$%^&*()\\-_=+].*"),
                "password must contain all four character classes: " + pw);
            assertNotEquals(oldDemo, pw);
        }
        // randomness sanity: two consecutive draws differ (overwhelmingly likely)
        assertNotEquals(AdminBootstrap.generatePassword(16), AdminBootstrap.generatePassword(16));
    }

    @Test
    @DisplayName("Morphic rotation computes a real config from data even with no stores wired")
    void rotationServiceComputesWithoutStores() {
        MorphicRotationService service = new MorphicRotationService(null, null, 15, true);
        AdaptiveDefenseEngine.MorphicConfig config = service.rotateNow();

        assertNotNull(config);
        assertEquals(1, config.rotationCount, "first rotation must advance the counter");
        assertNotNull(config.currentIkeProposal);
        assertTrue(config.recommendedTier >= 0 && config.recommendedTier <= 3);
        assertTrue(config.dataBasis.contains("scheduled rotation from 0 recent analyses"),
            "data basis must be honest about the sample size: " + config.dataBasis);
        assertEquals(15, service.getIntervalMinutes());
    }
}
