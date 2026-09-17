package com.ipsec;

import com.ipsec.api.AnalysisPipeline;
import com.ipsec.features.FeatureExtractor;
import com.ipsec.scoring.SecurityScorer;
import com.ipsec.support.PcapFixtures;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pcap4j.core.Pcaps;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the full analysis pipeline against a generated capture. Parsing
 * real pcap files requires the native libpcap library, so these tests only run
 * where it is installed (the Docker image and its test container).
 */
@SpringBootTest(properties = {
    "spring.datasource.url=jdbc:h2:mem:pipetest;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
    "spring.datasource.driverClassName=org.h2.Driver",
    "spring.datasource.username=sa",
    "spring.datasource.password=",
    "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "security.jwt.secret=test-secret-key-for-unit-tests-0123456789abcdef",
    "morphic.enabled=false",
    "admin.bootstrap-enabled=false"
})
class AnalysisPipelineTest {

    private static final long START = 1_700_000_000_000L;

    @Autowired
    private AnalysisPipeline analysisPipeline;

    @BeforeAll
    static void requireLibpcap() {
        Assumptions.assumeTrue(libpcapAvailable(),
            "native libpcap not available - skipping capture parsing tests");
    }

    private static boolean libpcapAvailable() {
        try {
            Pcaps.libVersion();
            return true;
        } catch (Throwable notAvailable) {
            return false;
        }
    }

    private static File capture(int espPackets, int protocol) throws Exception {
        File file = Files.createTempFile("ipsec-test-", ".pcap").toFile();
        PcapFixtures.writePcap(file, PcapFixtures.ipsecSession(espPackets, protocol, START));
        return file;
    }

    @Test
    @DisplayName("A generated capture yields real features, prediction and assessment")
    void analysesGeneratedCapture() throws Exception {
        File capture = capture(60, 50);
        List<String> progress = new ArrayList<>();

        Map<String, Object> result = analysisPipeline.run(
            capture, "generated.pcap", 1L, "127.0.0.1",
            null, null, null, false,
            (percent, status) -> progress.add(percent + "% " + status));

        FeatureExtractor.PacketFeatures features =
            (FeatureExtractor.PacketFeatures) result.get("features");
        SecurityScorer.SecurityAssessment assessment =
            (SecurityScorer.SecurityAssessment) result.get("assessment");

        assertEquals(4, features.ikeNegotiationCount);
        assertEquals(60, features.espPacketCount);
        assertEquals(0, features.ahPacketCount);
        assertEquals(50, features.ipsecProtocol);
        assertTrue(features.avgPacketSize > 0);
        assertTrue(features.avgInterArrivalTime > 0,
            "inter-arrival times must come from the capture, not wall clock");

        assertNotNull(result.get("prediction"));
        assertNotNull(assessment);
        assertTrue(assessment.overallRiskScore >= 0 && assessment.overallRiskScore <= 100);
        assertNotNull(assessment.riskLevel);

        assertTrue(progress.contains("5% Upload received"), "progress was reported: " + progress);
        assertTrue(progress.contains("100% Analysis complete"), "progress completed: " + progress);

        String executive = String.valueOf(result.get("executiveReport"));
        String technical = String.valueOf(result.get("technicalReport"));
        assertTrue(executive.contains("EXECUTIVE SUMMARY"));
        assertTrue(technical.contains("TECHNICAL ANALYSIS REPORT"));

        @SuppressWarnings("unchecked")
        Map<String, Object> configuration = (Map<String, Object>) result.get("configuration");
        assertEquals("assumed-defaults", configuration.get("source"),
            "without explicit parameters the configuration must be flagged as assumed");
    }

    @Test
    @DisplayName("Supplied configuration parameters change the assessment")
    void suppliedConfigurationIsUsed() throws Exception {
        File capture = capture(20, 50);

        Map<String, Object> assumed = analysisPipeline.run(
            capture, "assumed.pcap", 1L, "127.0.0.1", null, null, null, false, null);
        Map<String, Object> supplied = analysisPipeline.run(
            capture, "supplied.pcap", 1L, "127.0.0.1", 2, false, 86_400L, false, null);

        @SuppressWarnings("unchecked")
        Map<String, Object> assumedConfig = (Map<String, Object>) assumed.get("configuration");
        @SuppressWarnings("unchecked")
        Map<String, Object> suppliedConfig = (Map<String, Object>) supplied.get("configuration");

        assertEquals("assumed-defaults", assumedConfig.get("source"));
        assertEquals("provided-by-client", suppliedConfig.get("source"));
        assertEquals(2, suppliedConfig.get("dhGroup"));
        assertEquals(Boolean.FALSE, suppliedConfig.get("pfsEnabled"));

        SecurityScorer.SecurityAssessment weakAssessment =
            (SecurityScorer.SecurityAssessment) supplied.get("assessment");
        SecurityScorer.SecurityAssessment strongAssessment =
            (SecurityScorer.SecurityAssessment) assumed.get("assessment");

        assertTrue(weakAssessment.overallRiskScore > strongAssessment.overallRiskScore,
            "a weak DH group, disabled PFS and a long key lifetime must score worse");
        assertTrue(weakAssessment.vulnerabilities.stream()
                .anyMatch(v -> v.toLowerCase().contains("pfs")),
            "disabled PFS must be reported as a vulnerability");
    }

    @Test
    @DisplayName("AH captures are reported as protocol 51")
    void ahCaptureIsDetected() throws Exception {
        File capture = capture(10, 51);

        Map<String, Object> result = analysisPipeline.run(
            capture, "ah.pcap", 1L, "127.0.0.1", null, null, null, false, null);

        FeatureExtractor.PacketFeatures features =
            (FeatureExtractor.PacketFeatures) result.get("features");

        assertEquals(10, features.ahPacketCount);
        assertEquals(51, features.ipsecProtocol);
    }

    @Test
    @DisplayName("A non-pcap upload fails gracefully instead of throwing")
    void malformedCaptureIsHandled() throws Exception {
        File notACapture = Files.createTempFile("not-a-pcap-", ".pcap").toFile();
        Files.writeString(notACapture.toPath(), "this is definitely not a pcap file");

        Map<String, Object> result = analysisPipeline.run(
            notACapture, "broken.pcap", 1L, "127.0.0.1", null, null, null, false, null);

        assertNotNull(result.get("features"), "analysis should still return a result");
        assertNotNull(result.get("assessment"));
    }
}
