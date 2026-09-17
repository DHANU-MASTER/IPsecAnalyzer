package com.ipsec.store;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/** A threat event observed by one mesh node, shared with the collective. */
@Entity
@Table(name = "mesh_events")
public class MeshEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String eventId;

    @Column(nullable = false)
    private String reporterNodeId;

    @Column(nullable = false)
    private String threatType;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String description;

    /** HMAC-SHA256(eventId|reporter|threatType|description) - integrity seal. */
    @Column(nullable = false)
    private String signature;

    /** Verification key id, so receivers know which secret produced the HMAC. */
    @Column(nullable = false)
    private String keyId;

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    public MeshEventEntity() {
    }

    public Long getId() { return id; }
    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }
    public String getReporterNodeId() { return reporterNodeId; }
    public void setReporterNodeId(String reporterNodeId) { this.reporterNodeId = reporterNodeId; }
    public String getThreatType() { return threatType; }
    public void setThreatType(String threatType) { this.threatType = threatType; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }
    public String getKeyId() { return keyId; }
    public void setKeyId(String keyId) { this.keyId = keyId; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}
