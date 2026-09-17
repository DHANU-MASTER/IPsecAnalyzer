package com.ipsec;

import com.ipsec.crypto.CryptoKit;
import com.ipsec.store.MeshEventRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the mesh gossip ingestion path end-to-end over MockMvc:
 *  - a correctly HMAC-SHA256-signed event is accepted AND persisted
 *  - a forged signature is rejected and never stored
 */
@SpringBootTest(properties = {
    "spring.datasource.url=jdbc:h2:mem:meshtest;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
    "spring.datasource.driverClassName=org.h2.Driver",
    "spring.datasource.username=sa",
    "spring.datasource.password=",
    "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "security.jwt.secret=test-secret-key-for-unit-tests-0123456789abcdef",
    "morphic.enabled=false",
    "admin.bootstrap-enabled=false"
})
@AutoConfigureMockMvc
class MeshGossipTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private MeshEventRepository eventRepository;

    private static String sign(String eventId, String reporter, String type, String description) {
        return CryptoKit.hmacSha256Hex("demo-mesh-key-change-me".getBytes(StandardCharsets.UTF_8),
            eventId + "|" + reporter + "|" + type + "|" + description);
    }

    @Test
    @DisplayName("Validly signed gossip event is accepted and stored")
    void validSignatureAcceptedAndStored() throws Exception {
        long before = eventRepository.count();

        String eventId = "evt-test-" + System.nanoTime();
        String body = """
            {
              "eventId": "%s",
              "reporterNodeId": "junit-peer-01",
              "threatType": "WEAK_CRYPTO_DETECTED",
              "description": "3DES tunnel observed in unit test",
              "signature": "%s",
              "keyId": "hmac-sha256:junit-peer-01"
            }
            """.formatted(eventId, sign(
                eventId, "junit-peer-01", "WEAK_CRYPTO_DETECTED", "3DES tunnel observed in unit test"));

        mockMvc.perform(post("/api/mesh/gossip")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accepted").value(true))
            .andExpect(jsonPath("$.signatureValid").value(true))
            .andExpect(jsonPath("$.stored").value(true));

        assertTrue(eventRepository.count() == before + 1,
            "the signed event must be persisted");
    }

    @Test
    @DisplayName("Forged signature is rejected and never stored")
    void forgedSignatureRejected() throws Exception {
        long before = eventRepository.count();

        String body = """
            {
              "eventId": "evt-forged-%d",
              "reporterNodeId": "junit-attacker",
              "threatType": "WEAK_CRYPTO_DETECTED",
              "description": "injected forgery",
              "signature": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
              "keyId": "hmac-sha256:junit-attacker"
            }
            """.formatted(System.nanoTime());

        mockMvc.perform(post("/api/mesh/gossip")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accepted").value(false))
            .andExpect(jsonPath("$.signatureValid").value(false));

        assertTrue(eventRepository.count() == before,
            "a forged event must never reach the database");
    }
}
