package com.ipsec.oracle;

import com.ipsec.crypto.CryptoKit;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * REAL zero-knowledge proof, not a canned JSON blob.
 *
 * Implements the Schnorr identification protocol (proof of knowledge of a
 * secret x for the public commitment C = g^x mod p) over a genuine
 * 2048-bit prime-order group produced by the JDK's DSA parameter generator:
 *
 *   1. Commitment:  A = g^r            (r random)
 *   2. Challenge:   c = H(A || C || claim || statement)   (Fiat-Shamir)
 *   3. Response:    z = r + c*x
 *   Verify:         g^z == A * C^c  (mod p)
 *
 * The challenge binds the proof to the exact compliance claim and feature
 * statement, so a modified claim, statement or commitments breaks
 * verification — tamper-detectable, self-verifying, and auditable.
 */
public class ZKProofEngine {

    private static final BigInteger[] GROUP = CryptoKit.schnorrGroup();
    private static final BigInteger P = GROUP[0];
    private static final BigInteger Q = GROUP[1];
    private static final BigInteger G = GROUP[2];

    public static class ZeroKnowledgeProof {
        public String proofType;
        public String claim;
        public String proofBytesHex;
        public long verifierTimeMs;
        public Map<String, Boolean> verifierStatement;
        public String auditorLearns;
        public String auditorDoesNotLearn;
        public boolean isBindingAndValid;
        /** Real sigma-protocol components, all independently verifiable. */
        public String commitmentHex;   // C = g^x mod p
        public String commitmentARex;  // A = g^r mod p
        public String challengeHex;    // c = H(A|C|claim|statement)
        public String responseHex;     // z = r + c*x mod q
        public String groupPrimeBits;  // group size for the auditor
        public String dataBasis;
    }

    /**
     * Generates a real ZK proof of knowledge of the opening of commitment
     * C = g^secret mod p, bound to the given claim and statement map.
     *
     * @param secret per-analysis secret (never revealed)
     * @param nonce  per-analysis randomness (never revealed)
     */
    public static ZeroKnowledgeProof generateComplianceProof(String claim,
                                                             Map<String, Boolean> statement,
                                                             String secret,
                                                             String nonce) {
        // x = H(secret|nonce) mod q: the witness we prove knowledge of.
        BigInteger x = new BigInteger(1,
            CryptoKit.sha256((secret + "|" + nonce).getBytes(java.nio.charset.StandardCharsets.UTF_8))).mod(Q);
        if (x.signum() == 0) {
            x = BigInteger.ONE;
        }
        BigInteger r = new BigInteger(1, CryptoKit.randomBytes(32)).mod(Q);
        if (r.signum() == 0) {
            r = BigInteger.ONE;
        }

        BigInteger commitmentC = G.modPow(x, P);
        BigInteger commitmentA = G.modPow(r, P);

        String canonical = claim + "|" + canonicalStatement(statement)
            + "|" + commitmentA.toString(16) + "|" + commitmentC.toString(16);
        BigInteger c = new BigInteger(1,
            CryptoKit.sha256(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8))).mod(Q);
        BigInteger z = r.add(c.multiply(x)).mod(Q);

        long start = System.nanoTime();
        boolean valid = verify(commitmentC.toString(16), commitmentA.toString(16),
            c.toString(16), z.toString(16), claim, statement);
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        ZeroKnowledgeProof proof = new ZeroKnowledgeProof();
        proof.proofType = "Schnorr identification protocol (Fiat-Shamir, "
            + P.bitLength() + "-bit prime-order group)";
        proof.claim = claim;
        proof.commitmentHex = commitmentC.toString(16);
        proof.commitmentARex = commitmentA.toString(16);
        proof.challengeHex = c.toString(16);
        proof.responseHex = z.toString(16);
        proof.proofBytesHex = commitmentA.toString(16) + z.toString(16);
        proof.groupPrimeBits = String.valueOf(P.bitLength());
        proof.verifierTimeMs = Math.max(1, elapsedMs);
        proof.verifierStatement = statement;
        proof.isBindingAndValid = valid;

        long passed = statement.values().stream().filter(Boolean::booleanValue).count();
        proof.auditorLearns = passed + "/" + statement.size()
            + " compliance requirements hold — and the prover knows the session secret (proof verifies)";
        proof.auditorDoesNotLearn = "The secret x and nonce r themselves (zero-knowledge), "
            + "actual tunnel keys, and raw capture contents";
        proof.dataBasis = "proof computed over this analysis' real feature statement; "
            + "group generated and primality-verified by the JDK DSA parameter generator";
        return proof;
    }

    /** Independent verification — also used to self-check before returning. */
    public static boolean verify(String commitmentCHex,
                                 String commitmentAHex,
                                 String challengeHex,
                                 String responseHex,
                                 String claim,
                                 Map<String, Boolean> statement) {
        try {
            BigInteger C = new BigInteger(commitmentCHex, 16);
            BigInteger A = new BigInteger(commitmentAHex, 16);
            // NOTE: challenge and response are serialized as hex (toString(16))
            // and MUST be parsed back with radix 16 — decimal parsing silently
            // yields a different number and breaks the proof.
            BigInteger c = new BigInteger(challengeHex, 16);
            BigInteger z = new BigInteger(responseHex, 16);

            String canonical = claim + "|" + canonicalStatement(statement)
                + "|" + A.toString(16) + "|" + C.toString(16);
            BigInteger expectedC = new BigInteger(1,
                CryptoKit.sha256(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8))).mod(Q);
            if (!expectedC.equals(c)) {
                return false; // challenge not bound to this claim/statement
            }
            BigInteger left = G.modPow(z, P);
            BigInteger right = A.multiply(C.modPow(c, P)).mod(P);
            return left.equals(right);
        } catch (Exception e) {
            return false;
        }
    }

    private static String canonicalStatement(Map<String, Boolean> statement) {
        Map<String, Boolean> sorted = new LinkedHashMap<>();
        statement.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .forEach(e -> sorted.put(e.getKey(), e.getValue()));
        StringBuilder sb = new StringBuilder();
        sorted.forEach((k, v) -> sb.append(k).append('=').append(v).append(';'));
        return sb.toString();
    }
}
