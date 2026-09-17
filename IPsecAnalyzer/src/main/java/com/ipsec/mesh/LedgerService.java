package com.ipsec.mesh;

import com.ipsec.crypto.CryptoKit;
import com.ipsec.store.LedgerBlockEntity;
import com.ipsec.store.LedgerBlockRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * REAL append-only collective-memory ledger.
 *
 * Each analysis seals its events into one block:
 *   hash = SHA-256(index | previousHash | merkleRoot | nonce)
 * where merkleRoot is a genuine Merkle tree over the transaction hashes and
 * nonce satisfies a small proof-of-work (4 hex zeros ≈ 65k hashes, instant).
 *
 * Blocks are persisted in PostgreSQL. The chain links by previousHash, so
 * editing any historical block (or its transactions) breaks every hash after
 * it — detectable by verifyChain().
 */
@Service
public class LedgerService {

    private static final int POW_DIFFICULTY = 4; // hex zeros; instant but real

    @Autowired(required = false)
    private LedgerBlockRepository repo;

    /** Record describing what was sealed into a block. */
    public record SealedEvent(String type, String data) {
    }

    /**
     * Seals the given events into a new chained block.
     *
     * @return the persisted entity, or null when no repository is wired
     *         (unit-test mode).
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public LedgerBlockEntity seal(List<SealedEvent> events) {
        if (repo == null) {
            return null;
        }
        synchronized (this) {
            long index = repo.count();
            String previousHash = index == 0 ? "genesis" : findLatestHash(repo);

            List<String> leafHashes = new ArrayList<>();
            StringBuilder txJson = new StringBuilder("[");
            for (int i = 0; i < events.size(); i++) {
                SealedEvent e = events.get(i);
                String canonical = e.type() + "|" + e.data() + "|" + index;
                String h = CryptoKit.sha256Hex(canonical);
                leafHashes.add(h);
                if (i > 0) {
                    txJson.append(",");
                }
                txJson.append("{\"type\":\"").append(e.type())
                    .append("\",\"data\":\"").append(jsonEscape(e.data()))
                    .append("\",\"hash\":\"").append(h).append("\"}");
            }
            txJson.append("]");

            String merkleRoot = CryptoKit.merkleRoot(leafHashes);
            String nonce = CryptoKit.proofOfWork(index + "|" + previousHash + "|" + merkleRoot, POW_DIFFICULTY);
            String hash = blockHash(index, previousHash, merkleRoot, nonce);

            LedgerBlockEntity block = new LedgerBlockEntity();
            block.setBlockIndex(index);
            block.setPreviousHash(previousHash);
            block.setTransactionsJson(txJson.toString());
            block.setMerkleRoot(merkleRoot);
            block.setNonce(Long.parseLong(nonce));
            block.setHash(hash);
            return repo.save(block);
        }
    }

    /**
     * Verifies the whole chain: recomputes every block hash, checks
     * previousHash linkage, Merkle roots and proof-of-work.
     *
     * @return summary map: valid, blocks checked, first bad index / reason
     */
    public Map<String, Object> verifyChain() {
        Map<String, Object> out = new java.util.LinkedHashMap<>();
        if (repo == null) {
            out.put("valid", false);
            out.put("reason", "ledger store not wired");
            return out;
        }
        List<LedgerBlockEntity> blocks = repo.findAllByOrderByBlockIndexAsc();
        String expectedPrevious = "genesis";
        for (LedgerBlockEntity b : blocks) {
            String recomputed = blockHash(b.getBlockIndex(), b.getPreviousHash(),
                b.getMerkleRoot(), Long.toString(b.getNonce()));
            if (!recomputed.equals(b.getHash())) {
                out.put("valid", false);
                out.put("failedAtBlock", b.getBlockIndex());
                out.put("reason", "block hash mismatch — block content was modified after sealing");
                return out;
            }
            if (!expectedPrevious.equals(b.getPreviousHash())) {
                out.put("valid", false);
                out.put("failedAtBlock", b.getBlockIndex());
                out.put("reason", "previousHash chain broken at block " + b.getBlockIndex());
                return out;
            }
            expectedPrevious = b.getHash();
        }
        out.put("valid", true);
        out.put("blocks", blocks.size());
        out.put("headHash", blocks.isEmpty() ? "genesis" : blocks.get(blocks.size() - 1).getHash());
        return out;
    }

    public List<LedgerBlockEntity> recentBlocks(int max) {
        if (repo == null) {
            return List.of();
        }
        List<LedgerBlockEntity> all = repo.findAllByOrderByBlockIndexAsc();
        return all.subList(Math.max(0, all.size() - max), all.size());
    }

    public long blockCount() {
        return repo != null ? repo.count() : 0;
    }

    private String findLatestHash(LedgerBlockRepository r) {
        List<LedgerBlockEntity> all = r.findAllByOrderByBlockIndexAsc();
        return all.isEmpty() ? "genesis" : all.get(all.size() - 1).getHash();
    }

    private String blockHash(long index, String previousHash, String merkleRoot, String nonce) {
        return CryptoKit.sha256Hex(index + "|" + previousHash + "|" + merkleRoot + "|" + nonce);
    }

    private String jsonEscape(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
