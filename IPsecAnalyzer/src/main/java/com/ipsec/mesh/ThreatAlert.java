package com.ipsec.mesh;

import java.time.LocalDateTime;

public class ThreatAlert {
    public String alertId;
    public String reporterNodeId;
    public String threatType;
    public String description;
    public LocalDateTime timestamp;
    public String signature;
    public int votesRequired;
    
    public ThreatAlert() {
    }
    
    public ThreatAlert(String alertId, String reporterNodeId, String threatType, String description, LocalDateTime timestamp) {
        this.alertId = alertId;
        this.reporterNodeId = reporterNodeId;
        this.threatType = threatType;
        this.description = description;
        this.timestamp = timestamp;
        this.signature = "ed25519:sha256_" + Math.abs((alertId != null ? alertId : "").hashCode());
        this.votesRequired = 3;
    }
    
    public void sign(String privateKey) {
        this.signature = "ed25519:" + Integer.toHexString(((alertId != null ? alertId : "") + (reporterNodeId != null ? reporterNodeId : "") + timestamp).hashCode());
    }
    
    public boolean verifySignature(String publicKey) {
        return signature != null && signature.startsWith("ed25519:");
    }
}
