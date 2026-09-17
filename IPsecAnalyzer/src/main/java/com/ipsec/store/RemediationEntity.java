package com.ipsec.store;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/** Tracks the full lifecycle of one remediation action. */
@Entity
@Table(name = "remediation_actions")
public class RemediationEntity {

    public enum State { GENERATED, APPLIED, ROLLED_BACK }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String actionId;

    @Column(nullable = false)
    private String threatId;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String originalConfig;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String hardenedConfig;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private State state = State.GENERATED;

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    private LocalDateTime appliedAt;

    private LocalDateTime rolledBackAt;

    @Column(nullable = false)
    private double riskBefore;

    @Column(nullable = false)
    private double riskAfter;

    public RemediationEntity() {
    }

    public Long getId() { return id; }
    public String getActionId() { return actionId; }
    public void setActionId(String actionId) { this.actionId = actionId; }
    public String getThreatId() { return threatId; }
    public void setThreatId(String threatId) { this.threatId = threatId; }
    public String getOriginalConfig() { return originalConfig; }
    public void setOriginalConfig(String originalConfig) { this.originalConfig = originalConfig; }
    public String getHardenedConfig() { return hardenedConfig; }
    public void setHardenedConfig(String hardenedConfig) { this.hardenedConfig = hardenedConfig; }
    public State getState() { return state; }
    public void setState(State state) { this.state = state; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getAppliedAt() { return appliedAt; }
    public LocalDateTime getRolledBackAt() { return rolledBackAt; }
    public double getRiskBefore() { return riskBefore; }
    public void setRiskBefore(double riskBefore) { this.riskBefore = riskBefore; }
    public double getRiskAfter() { return riskAfter; }
    public void setRiskAfter(double riskAfter) { this.riskAfter = riskAfter; }

    public void apply() {
        this.state = State.APPLIED;
        this.appliedAt = LocalDateTime.now();
    }

    public void rollback() {
        this.state = State.ROLLED_BACK;
        this.rolledBackAt = LocalDateTime.now();
    }
}
