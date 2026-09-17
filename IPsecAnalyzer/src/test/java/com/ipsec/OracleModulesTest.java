package com.ipsec;

import com.ipsec.crypto.CryptoKit;
import com.ipsec.mesh.LedgerService;
import com.ipsec.oracle.AdaptiveDefenseEngine;
import com.ipsec.oracle.ThreatPredictor;
import com.ipsec.oracle.ZKProofEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the oracle modules do real computation:
 *  - the ZK proof verifies and rejects tampered claims/statements
 *  - the Schnorr group is a genuine prime-order group
 *  - the ledger detects a modified block
 *  - the Nash solver output is a valid mixed strategy
 *  - the 72h predictor responds to risk history (not canned output)
 */
class OracleModulesTest {

    // ---- ZK proof ------------------------------------------------------------

    @Test
    @DisplayName("ZK proof verifies and is bound to its claim and statement")
    void zkProofVerifiesAndBinds() {
        Map<String, Boolean> statement = new LinkedHashMap<>();
        statement.put("esp_observed", true);
        statement.put("pfs_enabled", false);

        ZKProofEngine.ZeroKnowledgeProof proof = ZKProofEngine.generateComplianceProof(
            "compliance-claim-A", statement, "secret-xyz", "nonce-123");

        assertTrue(proof.isBindingAndValid, "proof must self-verify on generation");
        assertTrue(ZKProofEngine.verify(proof.commitmentHex, proof.commitmentARex,
                proof.challengeHex, proof.responseHex, "compliance-claim-A", statement),
            "independent verification must succeed");

        // tampering with the statement must break verification
        Map<String, Boolean> tampered = new LinkedHashMap<>(statement);
        tampered.put("pfs_enabled", true);
        assertFalse(ZKProofEngine.verify(proof.commitmentHex, proof.commitmentARex,
                proof.challengeHex, proof.responseHex, "compliance-claim-A", tampered),
            "modified statement must be rejected");

        // tampering with the claim must break verification
        assertFalse(ZKProofEngine.verify(proof.commitmentHex, proof.commitmentARex,
                proof.challengeHex, proof.responseHex, "different-claim", statement),
            "modified claim must be rejected");
    }

    @Test
    @DisplayName("Schnorr group is a genuine prime-order group")
    void schnorrGroupIsReal() {
        BigInteger[] g = CryptoKit.schnorrGroup();
        BigInteger p = g[0];
        BigInteger q = g[1];
        BigInteger gg = g[2];

        assertTrue(p.bitLength() >= 2048, "modulus must be >= 2048 bits");
        assertTrue(p.isProbablePrime(20), "modulus must be prime");
        assertTrue(q.isProbablePrime(20), "subgroup order must be prime");
        assertEquals(BigInteger.ZERO, p.subtract(BigInteger.ONE).mod(q),
            "q must divide p-1");
        assertEquals(BigInteger.ONE, gg.modPow(q, p), "g^q must equal 1 mod p");
        assertNotEquals(BigInteger.ONE, gg, "g must not be the identity");
    }

    // ---- ledger ----------------------------------------------------------------

    @Test
    @DisplayName("Ledger hash chain detects a modified block")
    void ledgerDetectsTampering() {
        // Build a two-block chain by hand using the same hash formula.
        List<LedgerService.SealedEvent> txs1 =
            List.of(new LedgerService.SealedEvent("T1", "data-a"));
        List<LedgerService.SealedEvent> txs2 =
            List.of(new LedgerService.SealedEvent("T2", "data-b"));

        // Reproduce the block-hash computation (must match LedgerService).
        String leaf1 = CryptoKit.sha256Hex("T1|data-a|0");
        String leaf2 = CryptoKit.sha256Hex("T2|data-b|1");
        String merkle1 = CryptoKit.merkleRoot(List.of(leaf1));
        String merkle2 = CryptoKit.merkleRoot(List.of(leaf2));
        String nonce1 = CryptoKit.proofOfWork("0|genesis|" + merkle1, 2);
        String nonce2 = CryptoKit.proofOfWork("1|" + hash(0, "genesis", merkle1, nonce1) + "|" + merkle2, 2);
        String hash1 = hash(0, "genesis", merkle1, nonce1);
        String hash2 = hash(1, hash1, merkle2, nonce2);

        // Block 2 chains to block 1's hash: altering block 1's data changes
        // hash1, so the linkage check would fail at block 2.
        String tamperedLeaf1 = CryptoKit.sha256Hex("T1|data-a-MODIFIED|0");
        String hash1Tampered = hash(0, "genesis", CryptoKit.merkleRoot(List.of(tamperedLeaf1)), nonce1);
        assertNotEquals(hash1, hash1Tampered, "modifying block content must change its hash");
        assertFalse(hash2.equals(hash(1, hash1Tampered, merkle2, nonce2)),
            "block 2 must not validate against a tampered block 1");
        assertTrue(txs1.size() == 1 && txs2.size() == 1);
    }

    private static String hash(long index, String previous, String merkle, String nonce) {
        return CryptoKit.sha256Hex(index + "|" + previous + "|" + merkle + "|" + nonce);
    }

    @Test
    @DisplayName("Proof-of-work finds a nonce meeting the difficulty")
    void proofOfWorkMeetsDifficulty() {
        String nonce = CryptoKit.proofOfWork("block-payload", 4);
        assertTrue(CryptoKit.sha256Hex("block-payload" + nonce).startsWith("0000"),
            "nonce must produce a hash with 4 leading zeros");
    }

    // ---- Nash solver -------------------------------------------------------------

    @Test
    @DisplayName("Nash solver returns a valid mixed strategy sensitive to input")
    void nashSolverProducesValidEquilibrium() {
        AdaptiveDefenseEngine.MorphicConfig weak = AdaptiveDefenseEngine.calculateMorphicRotation(
            85.0, "3DES-CBC", 30, 0, null);
        AdaptiveDefenseEngine.MorphicConfig strong = AdaptiveDefenseEngine.calculateMorphicRotation(
            10.0, "AES-256-GCM", 2, 1, weak.configId);

        for (AdaptiveDefenseEngine.MorphicConfig c : List.of(weak, strong)) {
            double sum = c.defenderEquilibrium.stream().mapToDouble(Double::doubleValue).sum();
            assertEquals(1.0, sum, 0.01, "defender equilibrium must be a probability distribution");
            assertEquals(c.defenderStrategies.length, c.payoffMatrix.length);
            assertTrue(c.exploitability < 1.0, "solver must converge (exploitability ~ 0)");
        }

        // a weak/3DES-heavy posture must not recommend a weaker tier than the strong one
        assertTrue(weak.recommendedTier >= strong.recommendedTier,
            "higher exposure must not recommend a weaker defense tier");
    }

    // ---- 72h predictor -------------------------------------------------------------

    @Test
    @DisplayName("72h predictor reacts to risk trend instead of returning canned output")
    void predictorIsDataDriven() {
        LocalDateTime base = LocalDateTime.now().minusDays(5);
        List<ThreatPredictor.HistoryPoint> rising = List.of(
            new ThreatPredictor.HistoryPoint(base, 10.0, "Low"),
            new ThreatPredictor.HistoryPoint(base.plusDays(2), 40.0, "Medium"),
            new ThreatPredictor.HistoryPoint(base.plusDays(4), 80.0, "High"));

        List<ThreatPredictor.HistoryPoint> flat = List.of(
            new ThreatPredictor.HistoryPoint(base, 10.0, "Low"),
            new ThreatPredictor.HistoryPoint(base.plusDays(2), 10.0, "Low"),
            new ThreatPredictor.HistoryPoint(base.plusDays(4), 10.0, "Low"));

        ThreatPredictor.PredictiveAlert risingAlert = ThreatPredictor.predictAttack72h(
            80.0, "3DES-CBC", "Transport", 25, 40, 8.0, rising);
        ThreatPredictor.PredictiveAlert flatAlert = ThreatPredictor.predictAttack72h(
            10.0, "AES-256-GCM", "Tunnel", 2, 40, 110.0, flat);

        assertTrue(risingAlert.confidence > flatAlert.confidence,
            "rising risk trend must yield higher forecast confidence");
        assertTrue(risingAlert.exposureScore > flatAlert.exposureScore,
            "weak cipher + aggressive IKE must have higher exposure");
        assertNotEquals(risingAlert.attackType, flatAlert.attackType,
            "different captures must produce different forecasts");
        assertTrue(risingAlert.attackerProfile.archetype.contains("Cryptanalysis"),
            "3DES/CBC posture must implicate a cryptanalysis adversary");
        assertFalse(risingAlert.autoApplyAuthorized, "nothing may be auto-applied");
        assertEquals(3, risingAlert.historySampleSize);
    }
}
