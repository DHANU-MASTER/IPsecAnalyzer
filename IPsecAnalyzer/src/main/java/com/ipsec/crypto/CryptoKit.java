package com.ipsec.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.DSAParameterSpec;
import java.security.AlgorithmParameterGenerator;
import java.util.HexFormat;

/**
 * Small, dependency-free cryptographic toolkit:
 *  - SHA-256 hashing and HMAC
 *  - Finite-field arithmetic over a large prime (for Pedersen commitments)
 *  - Merkle tree roots
 *  - Hashcash-style proof-of-work
 *
 * Everything is standard JDK (no BouncyCastle), so it works in the slim runtime image.
 */
public final class CryptoKit {

    private CryptoKit() {
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static String sha256Hex(String data) {
        return HexFormat.of().formatHex(sha256(data.getBytes(StandardCharsets.UTF_8)));
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    public static String hmacSha256Hex(byte[] key, String data) {
        return HexFormat.of().formatHex(hmacSha256(key, data.getBytes(StandardCharsets.UTF_8)));
    }

    public static byte[] randomBytes(int n) {
        byte[] out = new byte[n];
        new SecureRandom().nextBytes(out);
        return out;
    }

    /** Concatenation hash H(a || b) used inside the Merkle tree. */
    public static String hashPair(String leftHex, String rightHex) {
        return sha256Hex(leftHex + rightHex);
    }

    /**
     * Merkle root over the given leaves (single leaf hashes to itself,
     * odd leaf is duplicated with itself, standard Bitcoin-style rule).
     */
    public static String merkleRoot(java.util.List<String> leafHashes) {
        if (leafHashes == null || leafHashes.isEmpty()) {
            return sha256Hex("empty");
        }
        java.util.List<String> level = new java.util.ArrayList<>(leafHashes);
        while (level.size() > 1) {
            java.util.List<String> next = new java.util.ArrayList<>();
            for (int i = 0; i < level.size(); i += 2) {
                String left = level.get(i);
                String right = (i + 1 < level.size()) ? level.get(i + 1) : left;
                next.add(hashPair(left, right));
            }
            level = next;
        }
        return level.get(0);
    }

    /**
     * Finds a nonce so that sha256Hex(payload + nonce) starts with
     * {@code difficultyHexChars} zeros. Difficulty 4 is instant; 6 is < 1s.
     */
    public static String proofOfWork(String payload, int difficultyHexChars) {
        String prefix = "0".repeat(difficultyHexChars);
        long nonce = 0;
        while (true) {
            String candidate = sha256Hex(payload + nonce);
            if (candidate.startsWith(prefix)) {
                return Long.toString(nonce);
            }
            nonce++;
        }
    }

    // ---- Schnorr / DSA-style group for the ZK engine ------------------------

    private static volatile BigInteger[] schnorrGroup; // {p, q, g}

    /**
     * A genuine 2048-bit prime-order group for the Schnorr proofs: p, q and g
     * are produced by the JDK's own DSA parameter generator (which primality-
     * verifies p and q) with a fixed seed, so every deployment derives the
     * identical group. No hand-typed constants — the group is really prime.
     *
     * @return array of {p, q, g}
     */
    public static synchronized BigInteger[] schnorrGroup() {
        if (schnorrGroup == null) {
            try {
                SecureRandom drand = SecureRandom.getInstance("SHA1PRNG");
                drand.setSeed(sha256("ipsec-analyzer-schnorr-group-seed-v1"
                    .getBytes(StandardCharsets.UTF_8)));
                AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DSA");
                gen.init(2048, drand);
                DSAParameterSpec spec =
                    gen.generateParameters().getParameterSpec(DSAParameterSpec.class);
                schnorrGroup = new BigInteger[]{spec.getP(), spec.getQ(), spec.getG()};
            } catch (Exception e) {
                throw new IllegalStateException("Cannot generate Schnorr group", e);
            }
        }
        return schnorrGroup;
    }
}
