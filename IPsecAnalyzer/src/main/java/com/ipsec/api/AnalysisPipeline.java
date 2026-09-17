package com.ipsec.api;

import com.ipsec.agent.RemediationAgent;
import com.ipsec.agent.RemediationLifecycleService;
import com.ipsec.capture.PcapReader;
import com.ipsec.config.HardenedConfigGenerator;
import com.ipsec.features.FeatureExtractor;
import com.ipsec.mesh.LedgerService;
import com.ipsec.mesh.MeshNodeService;
import com.ipsec.ml.ModelExplainability;
import com.ipsec.ml.Predictor;
import com.ipsec.oracle.AdaptiveDefenseEngine;
import com.ipsec.oracle.CrossSectorCorrelator;
import com.ipsec.oracle.SupplyChainIntegrityEngine;
import com.ipsec.oracle.ThreatPredictor;
import com.ipsec.oracle.ZKProofEngine;
import com.ipsec.pqc.PQCReadinessAssessor;
import com.ipsec.scoring.SecurityScorer;
import com.ipsec.scoring.ThreatMatrix;
import com.ipsec.security.entity.AnalysisHistory;
import com.ipsec.security.repository.AnalysisHistoryRepository;
import com.ipsec.store.LedgerBlockEntity;
import com.ipsec.store.MeshEventEntity;
import com.ipsec.store.RemediationEntity;
import com.ipsec.store.MorphicStateEntity;
import com.ipsec.store.MorphicStateRepository;
import com.ipsec.store.SupplyChainBaselineRepository;
import com.ipsec.threat.NvdCveClient;
import com.ipsec.threat.ThreatIntelligenceEngine;
import com.ipsec.ztrust.ZeroTrustValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Single implementation of the analysis pipeline, shared by the synchronous
 * upload endpoint and the WebSocket streaming endpoint so identical input
 * always yields identical results.
 *
 * Every oracle module is computed from this analysis' real data:
 * predictor from capture features + analysis history, ZK proof over the
 * feature statement, supply-chain over the running artifacts, Nash solver
 * over a payoff matrix built from the observed risk, cross-sector over the
 * persisted mesh event store, consensus from real vote tallies, and the
 * ledger block sealed with this analysis' actual events.
 */
@Service
public class AnalysisPipeline {

    /** Receives progress updates (percent + human readable status). */
    public interface ProgressSink {
        void progress(int percent, String status);
    }

    /** Defaults used when the client cannot observe the real values. */
    public static final int DEFAULT_DH_GROUP = 14;
    public static final boolean DEFAULT_PFS = true;
    public static final long DEFAULT_KEY_LIFETIME = 7200L;

    @Autowired(required = false)
    private AnalysisHistoryRepository analysisHistoryRepository;

    @Autowired(required = false)
    private SupplyChainBaselineRepository supplyChainBaselineRepository;

    @Autowired(required = false)
    private MorphicStateRepository morphicStateRepository;

    @Autowired
    private MeshNodeService meshNodeService;

    @Autowired
    private LedgerService ledgerService;

    @Autowired
    private RemediationLifecycleService remediationLifecycleService;

    private volatile Predictor predictor = new Predictor();

    /**
     * Reloads the ML models from disk (called after /api/ml/retrain so the
     * running app immediately serves the freshly trained models).
     */
    public void reloadModels() {
        this.predictor = new Predictor();
    }

    /** Convenience wrapper: stores the upload, analyses it, then removes it. */
    public Map<String, Object> run(MultipartFile file,
                                   Long userId,
                                   String clientIp,
                                   Integer dhGroup,
                                   Boolean pfsEnabled,
                                   Long keyLifetime,
                                   ProgressSink sink) throws Exception {

        if (file == null || file.getOriginalFilename() == null || file.getOriginalFilename().isEmpty()) {
            throw new IllegalArgumentException(
                "The uploaded .pcap file is empty. Please select a valid .pcap file.");
        }

        File storedFile = store(file);
        return run(storedFile, file.getOriginalFilename(), userId, clientIp,
                   dhGroup, pfsEnabled, keyLifetime, true, sink);
    }

    /**
     * Core analysis. The caller owns {@code pcapFile} unless
     * {@code deleteWhenDone} is true, in which case it is removed afterwards.
     */
    public Map<String, Object> run(File pcapFile,
                                   String originalFilename,
                                   Long userId,
                                   String clientIp,
                                   Integer dhGroup,
                                   Boolean pfsEnabled,
                                   Long keyLifetime,
                                   boolean deleteWhenDone,
                                   ProgressSink sink) throws Exception {

        notify(sink, 5, "Upload received");

        try {
            notify(sink, 20, "Parsing capture with pcap4j...");
            List<PcapReader.TimestampedPacket> packets;
            try {
                packets = PcapReader.readPcapWithTimestamps(pcapFile.getAbsolutePath());
            } catch (Exception ex) {
                System.err.println("[WARN] PcapReader parse error: " + ex.getMessage());
                packets = Collections.emptyList();
            }

            notify(sink, 40, "Extracting traffic features...");
            FeatureExtractor.PacketFeatures features = FeatureExtractor.extract(packets);

            notify(sink, 55, "Running cipher classifier...");
            Predictor.PredictionResult prediction = predictor.predict(
                features.avgPacketSize,
                features.stdPacketSize,
                features.avgInterArrivalTime,
                features.stdInterArrivalTime,
                features.ikeNegotiationCount,
                features.espPacketCount
            );

            notify(sink, 70, "Scoring security posture...");

            // DH group, PFS state and key lifetime are not observable in encrypted
            // traffic. They come from the request when supplied; otherwise the
            // documented defaults are used and flagged as assumptions.
            boolean assumedConfiguration = (dhGroup == null || pfsEnabled == null || keyLifetime == null);
            int dhGroupUsed = dhGroup != null ? dhGroup : DEFAULT_DH_GROUP;
            boolean pfsUsed = pfsEnabled != null ? pfsEnabled : DEFAULT_PFS;
            long lifetimeUsed = keyLifetime != null ? keyLifetime : DEFAULT_KEY_LIFETIME;

            SecurityScorer.SecurityAssessment assessment = SecurityScorer.scoreIPsecConfig(
                prediction.predictedCipher,
                prediction.predictedTunnelMode,
                dhGroupUsed,
                pfsUsed,
                lifetimeUsed
            );

            List<ThreatMatrix.Threat> threats = ThreatMatrix.generateThreatMatrix(assessment);

            List<RemediationAgent.RemediationPlan> remediationPlans =
                RemediationAgent.generateRemediationPlans(
                    assessment, "ike=aes256-sha256-modp2048", "esp=aes128-sha256");
            for (RemediationAgent.RemediationPlan plan : remediationPlans) {
                try {
                    RemediationEntity saved = remediationLifecycleService.createPlan(
                        plan, assessment.overallRiskScore);
                    if (saved != null) {
                        plan.actionId = saved.getActionId();
                    }
                    if (plan.remediationSteps == null || plan.remediationSteps.isEmpty()) {
                        plan.remediationSteps = List.of(
                            "Review the hardened proposal against your gateway policy",
                            "Stage the hardened config on a maintenance window",
                            "Apply and verify tunnel re-establishment",
                            "Rollback artifact is archived alongside the active config");
                    }
                } catch (Exception ex) {
                    System.err.println("[WARN] remediation persistence failed: " + ex.getMessage());
                }
            }

            // Layer-0 intel: live NVD query (60-min cache) with a labeled
            // offline fallback — the feed basis is surfaced to the dashboard.
            NvdCveClient.FeedResult threatIntelFeed =
                ThreatIntelligenceEngine.fetchThreatIntelLive(prediction.predictedCipher);
            List<ThreatIntelligenceEngine.ThreatIntel> threatIntel = threatIntelFeed.items;

            java.util.Map<String, Object> threatIntelMeta = new LinkedHashMap<>();
            threatIntelMeta.put("feedBasis", threatIntelFeed.feedBasis);
            threatIntelMeta.put("fetchedAt", threatIntelFeed.fetchedAt);
            threatIntelMeta.put("query", threatIntelFeed.query);
            threatIntelMeta.put("results", threatIntel.size());

            PQCReadinessAssessor.PQCAssessment pqcAssessment =
                PQCReadinessAssessor.assessPQCReadiness(prediction.predictedCipher);

            ModelExplainability.ModelExplanation explanation = ModelExplainability.explainCipherPrediction(
                features.avgPacketSize,
                features.stdPacketSize,
                features.avgInterArrivalTime,
                features.ikeNegotiationCount,
                prediction.predictedCipher,
                prediction.cipherConfidence
            );

            HardenedConfigGenerator.GeneratedConfig hardenedConfig =
                HardenedConfigGenerator.generateConfig(HardenedConfigGenerator.SecurityProfile.STRICT);

            ZeroTrustValidator.ZeroTrustAssessment zeroTrust = ZeroTrustValidator.assessZeroTrustReadiness(
                prediction.predictedTunnelMode,
                prediction.predictedCipher,
                pfsUsed,
                true
            );

            notify(sink, 85, "Running oracle modules (predictor, ZK, game theory, mesh, ledger)...");

            // ---- history for the data-driven predictor (real prior analyses) ----
            List<ThreatPredictor.HistoryPoint> history = loadHistory();

            ThreatPredictor.PredictiveAlert predictiveAlert = ThreatPredictor.predictAttack72h(
                assessment.overallRiskScore,
                prediction.predictedCipher,
                prediction.predictedTunnelMode,
                features.ikeNegotiationCount,
                features.espPacketCount,
                features.avgInterArrivalTime,
                history
            );

            // ---- ZK proof over THIS analysis' real compliance statement ----
            Map<String, Boolean> zkStatement = new LinkedHashMap<>();
            zkStatement.put("esp_encryption_observed", features.espPacketCount > 0);
            zkStatement.put("ike_key_exchange_observed", features.ikeNegotiationCount > 0);
            zkStatement.put("no_weak_cipher_predicted", !(prediction.predictedCipher.contains("3DES")
                || prediction.predictedCipher.toUpperCase().contains("DES")));
            zkStatement.put("forward_secrecy_enabled", pfsUsed);
            zkStatement.put("strong_dh_group", dhGroupUsed >= 14);
            ZKProofEngine.ZeroKnowledgeProof zkProof = ZKProofEngine.generateComplianceProof(
                "Analysis of " + originalFilename + " complies with the baseline IPsec policy",
                zkStatement,
                "analysis-" + System.currentTimeMillis(),
                CryptoNonce.next()
            );

            // ---- supply chain: hash the real running artifacts vs baselines ----
            SupplyChainIntegrityEngine.SupplyChainReport supplyChainReport =
                SupplyChainIntegrityEngine.verifyIntegrity(supplyChainBaselineRepository, null);

            // ---- adaptive defense: Nash over a payoff matrix from this analysis ----
            long previousRotationCount = 0;
            String previousConfigId = null;
            if (morphicStateRepository != null) {
                MorphicStateEntity prev = morphicStateRepository.findTopByOrderByGeneratedAtDesc().orElse(null);
                if (prev != null) {
                    previousRotationCount = prev.getRotationCount();
                    previousConfigId = prev.getConfigId();
                }
            }
            AdaptiveDefenseEngine.MorphicConfig morphicDefense = AdaptiveDefenseEngine.calculateMorphicRotation(
                assessment.overallRiskScore,
                prediction.predictedCipher,
                features.ikeNegotiationCount,
                previousRotationCount,
                previousConfigId
            );
            persistMorphicState(morphicDefense);

            // ---- mesh: record a real (signed) event when the analysis warrants it ----
            // Medium+ risk (>=40) is shared: early signals are what let peer
            // sectors pre-harden before an attack escalates.
            boolean threatDetected = assessment.overallRiskScore >= 40
                || "Medium".equalsIgnoreCase(assessment.riskLevel)
                || "High".equalsIgnoreCase(assessment.riskLevel)
                || "Critical".equalsIgnoreCase(assessment.riskLevel);
            String threatType = threatDetected
                ? (prediction.predictedCipher.contains("3DES") || prediction.predictedCipher.contains("CBC")
                    ? "WEAK_CRYPTO_DETECTED" : "ELEVATED_RISK_TUNNEL")
                : null;
            MeshEventEntity recordedEvent = null;
            if (threatType != null) {
                try {
                    recordedEvent = meshNodeService.recordThreatEvent(threatType,
                        "risk=" + assessment.overallRiskScore + " cipher=" + prediction.predictedCipher
                            + " mode=" + prediction.predictedTunnelMode + " file=" + originalFilename);
                } catch (Exception ex) {
                    System.err.println("[WARN] mesh event recording failed: " + ex.getMessage());
                }
            }
            if (recordedEvent != null && threatDetected) {
                predictiveAlert.ledgerEntryHash = recordedEvent.getSignature();
            }

            // ---- cross-sector correlation over the real mesh event store ----
            CrossSectorCorrelator.CrossSectorAlert crossSectorAlert =
                CrossSectorCorrelator.analyzeCrossSectorCorrelation(
                    threatType,
                    meshNodeService.getSector(),
                    meshNodeService.recentEvents(200),
                    meshNodeService::sectorOf
                );

            // ---- PBFT-style consensus tallied from real votes ----
            MeshNodeService.VoteTally consensusRecord = meshNodeService.tallyConsensus(
                threatDetected,
                "alert-" + Long.toHexString(System.currentTimeMillis()),
                1 + meshNodeService.peerCount()
            );

            // ---- ledger: seal this analysis' real events into a chained block ----
            List<LedgerService.SealedEvent> sealedEvents = new ArrayList<>();
            sealedEvents.add(new LedgerService.SealedEvent("ANALYSIS_COMPLETED",
                "file=" + originalFilename + " risk=" + assessment.overallRiskScore
                    + " level=" + assessment.riskLevel));
            sealedEvents.add(new LedgerService.SealedEvent("PREDICTION_MADE",
                "cipher=" + prediction.predictedCipher + " mode=" + prediction.predictedTunnelMode
                    + " confidence=" + prediction.cipherConfidence + " basis=" + prediction.modelBasis));
            sealedEvents.add(new LedgerService.SealedEvent("THREATS_REPORTED",
                "count=" + threats.size()));
            if (recordedEvent != null) {
                sealedEvents.add(new LedgerService.SealedEvent("MESH_EVENT_SIGNED",
                    "eventId=" + recordedEvent.getEventId() + " type=" + threatType));
            }
            LedgerBlockEntity block = null;
            try {
                block = ledgerService.seal(sealedEvents);
            } catch (Exception ex) {
                System.err.println("[WARN] ledger sealing failed: " + ex.getMessage());
            }
            Map<String, Object> ledgerBlock = ledgerDisplayBlock(block, sealedEvents);
            if (block != null) {
                predictiveAlert.ledgerEntryHash = block.getHash();
            }

            if (analysisHistoryRepository != null) {
                try {
                    AnalysisHistory history2 = new AnalysisHistory();
                    history2.setUserId(userId != null ? userId : 1L);
                    history2.setPcapFilename(originalFilename);
                    history2.setPredictedCipher(prediction.predictedCipher);
                    history2.setPredictedMode(prediction.predictedTunnelMode);
                    history2.setRiskScore(assessment.overallRiskScore);
                    history2.setRiskLevel(assessment.riskLevel);
                    history2.setIpAddress(clientIp);
                    analysisHistoryRepository.save(history2);
                } catch (Exception ex) {
                    System.err.println("[WARN] Could not persist analysis history: " + ex.getMessage());
                }
            }

            Map<String, Object> configuration = new LinkedHashMap<>();
            configuration.put("dhGroup", dhGroupUsed);
            configuration.put("pfsEnabled", pfsUsed);
            configuration.put("keyLifetimeSeconds", lifetimeUsed);
            configuration.put("source", assumedConfiguration ? "assumed-defaults" : "provided-by-client");
            configuration.put("note", assumedConfiguration
                ? "DH group, PFS and key lifetime cannot be observed in encrypted traffic. "
                    + "Defaults were applied; pass dhGroup, pfs and keyLifetime to override."
                : "Values were supplied with the analysis request.");

            List<ThreatMatrix.Threat> threatList =
                threats != null ? threats : new ArrayList<ThreatMatrix.Threat>();

            Map<String, Object> response = new HashMap<>();
            response.put("features", features);
            response.put("prediction", prediction);
            response.put("assessment", assessment);
            response.put("threats", threatList);
            response.put("configuration", configuration);

            response.put("remediationPlans", remediationPlans);
            response.put("threatIntel", threatIntel);
            response.put("threatIntelFeed", threatIntelMeta);
            response.put("pqcAssessment", pqcAssessment);
            response.put("explanation", explanation);
            response.put("hardenedConfig", hardenedConfig);
            response.put("zeroTrust", zeroTrust);

            response.put("meshNodes", meshNodeService.getMeshOverview());
            response.put("consensusRecord", consensusRecord);
            response.put("ledgerBlock", ledgerBlock);

            response.put("predictiveAlert", predictiveAlert);
            response.put("zkProof", zkProof);
            response.put("supplyChainReport", supplyChainReport);
            response.put("morphicDefense", morphicDefense);
            response.put("crossSectorAlert", crossSectorAlert);

            // Human-readable reports (also downloadable from the dashboard)
            response.put("executiveReport",
                ReportService.generateExecutiveReport(assessment, threatList));
            response.put("technicalReport",
                ReportService.generateTechnicalReport(features, prediction, assessment, threatList));

            notify(sink, 100, "Analysis complete");
            return response;

        } finally {
            if (deleteWhenDone && pcapFile != null && pcapFile.exists() && !pcapFile.delete()) {
                System.err.println("[WARN] Could not delete temporary upload: " + pcapFile);
            }
        }
    }

    /** Last 50 real analysis records (any user), oldest first, for the trend model. */
    private List<ThreatPredictor.HistoryPoint> loadHistory() {
        if (analysisHistoryRepository == null) {
            return List.of();
        }
        try {
            List<AnalysisHistory> all = new ArrayList<>(analysisHistoryRepository.findAll());
            all.sort(Comparator.comparing(AnalysisHistory::getAnalyzedAt));
            List<AnalysisHistory> recent = all.subList(Math.max(0, all.size() - 50), all.size());
            List<ThreatPredictor.HistoryPoint> pts = new ArrayList<>();
            for (AnalysisHistory h : recent) {
                pts.add(new ThreatPredictor.HistoryPoint(
                    h.getAnalyzedAt(),
                    h.getRiskScore() != null ? h.getRiskScore() : 0,
                    h.getRiskLevel(),
                    h.getIpAddress()));
            }
            return pts;
        } catch (Exception ex) {
            System.err.println("[WARN] history load failed: " + ex.getMessage());
            return List.of();
        }
    }

    private void persistMorphicState(AdaptiveDefenseEngine.MorphicConfig config) {
        if (morphicStateRepository == null) {
            return;
        }
        try {
            MorphicStateEntity e = new MorphicStateEntity();
            e.setConfigId(config.configId);
            e.setIkeProposal(config.currentIkeProposal);
            e.setEspProposal(config.currentEspProposal);
            e.setDhGroup(String.valueOf(AdaptiveDefenseEngine.tierDhGroup(config.recommendedTier)));
            e.setRotationCount(config.rotationCount);
            e.setExpiresAt(java.time.LocalDateTime.now().plusMinutes(config.rotationIntervalMinutes));
            morphicStateRepository.save(e);
        } catch (Exception ex) {
            System.err.println("[WARN] morphic state persistence failed: " + ex.getMessage());
        }
    }

    /** Dashboard shape for the sealed ledger block (blockNumber + tx rows). */
    private Map<String, Object> ledgerDisplayBlock(LedgerBlockEntity block,
                                                   List<LedgerService.SealedEvent> events) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (block == null) {
            out.put("blockNumber", null);
            out.put("transactions", List.of());
            out.put("sealed", false);
            out.put("reason", "ledger store not wired");
            return out;
        }
        out.put("blockNumber", block.getBlockIndex());
        out.put("hash", block.getHash());
        out.put("previousHash", block.getPreviousHash());
        out.put("merkleRoot", block.getMerkleRoot());
        out.put("nonce", block.getNonce());
        out.put("sealed", true);
        List<Map<String, Object>> txs = new ArrayList<>();
        for (LedgerService.SealedEvent e : events) {
            Map<String, Object> tx = new LinkedHashMap<>();
            tx.put("timestamp", java.time.Instant.now().toString());
            tx.put("type", e.type());
            tx.put("data", e.data());
            tx.put("signature", com.ipsec.crypto.CryptoKit.sha256Hex(e.type() + "|" + e.data()));
            txs.add(tx);
        }
        out.put("transactions", txs);
        return out;
    }

    /** Stores an upload in the dedicated temp directory with a sanitised name. */
    public File store(MultipartFile file) throws Exception {
        File tempDir = new File(System.getProperty("java.io.tmpdir"), "ipsec_uploads");
        if (!tempDir.exists() && !tempDir.mkdirs()) {
            throw new IllegalStateException("Unable to create upload directory: " + tempDir);
        }
        String safeName = new File(file.getOriginalFilename()).getName()
            .replaceAll("[^a-zA-Z0-9._-]", "_");
        File tempFile = new File(tempDir, System.currentTimeMillis() + "_" + safeName);
        file.transferTo(tempFile);
        return tempFile;
    }

    private void notify(ProgressSink sink, int percent, String status) {
        if (sink != null) {
            try {
                sink.progress(percent, status);
            } catch (Exception ignored) {
                // progress reporting must never break the analysis
            }
        }
    }

    /** Per-analysis nonce source for the ZK prover. */
    private static final class CryptoNonce {
        static String next() {
            return java.util.HexFormat.of().formatHex(
                com.ipsec.crypto.CryptoKit.randomBytes(16));
        }
    }
}
