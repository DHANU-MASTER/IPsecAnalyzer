package com.ipsec.store;

import jakarta.persistence.*;

/** Baseline hash of a tracked binary, recorded the first time it is seen. */
@Entity
@Table(name = "supply_chain_baseline",
       uniqueConstraints = @UniqueConstraint(name = "uq_supply_component", columnNames = "component_name"))
public class SupplyChainBaselineEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "component_name", nullable = false, length = 512)
    private String componentName;

    @Column(name = "sha256", nullable = false, length = 64)
    private String sha256;

    @Column(name = "size_bytes", nullable = false)
    private long sizeBytes;

    @Column(name = "recorded_at", nullable = false)
    private java.time.LocalDateTime recordedAt = java.time.LocalDateTime.now();

    public Long getId() { return id; }
    public String getComponentName() { return componentName; }
    public void setComponentName(String componentName) { this.componentName = componentName; }
    public String getSha256() { return sha256; }
    public void setSha256(String sha256) { this.sha256 = sha256; }
    public long getSizeBytes() { return sizeBytes; }
    public void setSizeBytes(long sizeBytes) { this.sizeBytes = sizeBytes; }
    public java.time.LocalDateTime getRecordedAt() { return recordedAt; }
    public void setRecordedAt(java.time.LocalDateTime recordedAt) { this.recordedAt = recordedAt; }
}
