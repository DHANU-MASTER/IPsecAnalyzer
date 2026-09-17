package com.ipsec.store;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/** One block of the append-only collective memory ledger. */
@Entity
@Table(name = "ledger_blocks")
public class LedgerBlockEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "block_index", nullable = false, unique = true)
    private Long blockIndex;

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    /** JSON array of transactions sealed in this block. */
    @Column(nullable = false, columnDefinition = "TEXT")
    private String transactionsJson;

    @Column(nullable = false)
    private String merkleRoot;

    @Column(nullable = false)
    private String previousHash;

    /** SHA-256(index|previousHash|merkleRoot|nonce) with proof-of-work prefix. */
    @Column(nullable = false, unique = true)
    private String hash;

    @Column(nullable = false)
    private Long nonce;

    public LedgerBlockEntity() {
    }

    public Long getId() { return id; }
    public Long getBlockIndex() { return blockIndex; }
    public void setBlockIndex(Long blockIndex) { this.blockIndex = blockIndex; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    public String getTransactionsJson() { return transactionsJson; }
    public void setTransactionsJson(String transactionsJson) { this.transactionsJson = transactionsJson; }
    public String getMerkleRoot() { return merkleRoot; }
    public void setMerkleRoot(String merkleRoot) { this.merkleRoot = merkleRoot; }
    public String getPreviousHash() { return previousHash; }
    public void setPreviousHash(String previousHash) { this.previousHash = previousHash; }
    public String getHash() { return hash; }
    public void setHash(String hash) { this.hash = hash; }
    public Long getNonce() { return nonce; }
    public void setNonce(Long nonce) { this.nonce = nonce; }
}
