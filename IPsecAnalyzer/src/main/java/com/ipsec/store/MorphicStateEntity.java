package com.ipsec.store;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/** Current state of the adaptive morphic defense rotation. */
@Entity
@Table(name = "morphic_state")
public class MorphicStateEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String configId;

    @Column(nullable = false)
    private String ikeProposal;

    @Column(nullable = false)
    private String espProposal;

    @Column(nullable = false)
    private String dhGroup;

    @Column(nullable = false)
    private LocalDateTime generatedAt = LocalDateTime.now();

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    /** Count of rotations performed since startup. */
    @Column(nullable = false)
    private long rotationCount;

    public MorphicStateEntity() {
    }

    public Long getId() { return id; }
    public String getConfigId() { return configId; }
    public void setConfigId(String configId) { this.configId = configId; }
    public String getIkeProposal() { return ikeProposal; }
    public void setIkeProposal(String ikeProposal) { this.ikeProposal = ikeProposal; }
    public String getEspProposal() { return espProposal; }
    public void setEspProposal(String espProposal) { this.espProposal = espProposal; }
    public String getDhGroup() { return dhGroup; }
    public void setDhGroup(String dhGroup) { this.dhGroup = dhGroup; }
    public LocalDateTime getGeneratedAt() { return generatedAt; }
    public void setGeneratedAt(LocalDateTime generatedAt) { this.generatedAt = generatedAt; }
    public LocalDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }
    public long getRotationCount() { return rotationCount; }
    public void setRotationCount(long rotationCount) { this.rotationCount = rotationCount; }
}
