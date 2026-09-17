package com.ipsec.security.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "analysis_history")
public class AnalysisHistory {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private Long userId;
    
    @Column(name = "pcap_filename")
    private String pcapFilename;
    
    @Column(name = "predicted_cipher")
    private String predictedCipher;
    
    @Column(name = "predicted_mode")
    private String predictedMode;
    
    @Column(name = "risk_score")
    private Double riskScore;
    
    @Column(name = "risk_level")
    private String riskLevel;
    
    @Column(name = "analyzed_at")
    private LocalDateTime analyzedAt = LocalDateTime.now();
    
    @Column(name = "ip_address")
    private String ipAddress;
    
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
    
    public String getPcapFilename() { return pcapFilename; }
    public void setPcapFilename(String pcapFilename) { this.pcapFilename = pcapFilename; }
    
    public String getPredictedCipher() { return predictedCipher; }
    public void setPredictedCipher(String predictedCipher) { this.predictedCipher = predictedCipher; }
    
    public String getPredictedMode() { return predictedMode; }
    public void setPredictedMode(String predictedMode) { this.predictedMode = predictedMode; }
    
    public Double getRiskScore() { return riskScore; }
    public void setRiskScore(Double riskScore) { this.riskScore = riskScore; }
    
    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    
    public LocalDateTime getAnalyzedAt() { return analyzedAt; }
    public void setAnalyzedAt(LocalDateTime analyzedAt) { this.analyzedAt = analyzedAt; }
    
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
}
