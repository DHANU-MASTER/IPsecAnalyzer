package com.ipsec.oracle;

import com.ipsec.security.entity.AnalysisHistory;
import com.ipsec.security.repository.AnalysisHistoryRepository;
import com.ipsec.store.MorphicStateEntity;
import com.ipsec.store.MorphicStateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;

/**
 * Layer-5 morphic defense on a real clock: every {@code morphic.interval-minutes}
 * (default 15) a NEW configuration is generated from the current data — the
 * mean risk of recent analyses and the latest observed cipher — so "attackers
 * target old config, it's already changed" becomes an actual runtime behavior
 * instead of a per-analysis side effect.
 *
 * Rotation state is persisted in morphic_state (rotationCount, configId,
 * expiresAt) and each rotation's provenance labels its data basis. Disable
 * with {@code morphic.enabled=false} (the test profile does).
 */
@Service
public class MorphicRotationService {

    private final MorphicStateRepository morphicStateRepository;
    private final AnalysisHistoryRepository analysisHistoryRepository;
    private final long intervalMinutes;

    /** Toggled by {@code morphic.enabled}; volatile so the scheduler sees updates. */
    private volatile boolean enabled = true;

    @Autowired
    public MorphicRotationService(MorphicStateRepository morphicStateRepository,
                                  AnalysisHistoryRepository analysisHistoryRepository,
                                  @Value("${morphic.interval-minutes:15}") long intervalMinutes,
                                  @Value("${morphic.enabled:true}") boolean enabled) {
        this.morphicStateRepository = morphicStateRepository;
        this.analysisHistoryRepository = analysisHistoryRepository;
        this.intervalMinutes = intervalMinutes;
        this.enabled = enabled;
    }

    /**
     * The scheduled heartbeat. Fixed-delay keeps rotations evenly spaced even
     * if one run is slow; the first run happens one interval after startup.
     */
    @Scheduled(fixedDelayString = "#{${morphic.interval-minutes:15} * 60000}",
               initialDelayString = "#{${morphic.interval-minutes:15} * 60000}")
    public void rotate() {
        if (!enabled) {
            return;
        }
        try {
            AdaptiveDefenseEngine.MorphicConfig rotated = rotateNow();
            System.out.println("[Morphic] rotation #" + rotated.rotationCount
                + " -> " + rotated.currentIkeProposal
                + " (tier " + rotated.recommendedTier + "; " + rotated.dataBasis + ")");
        } catch (Exception ex) {
            // A failed rotation must never kill the scheduler thread.
            System.err.println("[Morphic] rotation failed: " + ex.getMessage());
        }
    }

    /**
     * Performs one rotation immediately from real data: recent analysis
     * history drives the risk input; the latest morphic row provides
     * rotation continuity. Shared by the scheduler, tests and the status API.
     */
    public AdaptiveDefenseEngine.MorphicConfig rotateNow() {
        List<AnalysisHistory> recent = analysisHistoryRepository != null
            ? analysisHistoryRepository.findTop50ByOrderByAnalyzedAtDesc()
            : List.of();

        double meanRisk = 0;
        String latestCipher = "AES-256-GCM";
        if (!recent.isEmpty()) {
            double sum = 0;
            for (AnalysisHistory h : recent) {
                sum += h.getRiskScore() != null ? h.getRiskScore() : 0;
            }
            meanRisk = sum / recent.size();
            latestCipher = recent.get(0).getPredictedCipher() != null
                ? recent.get(0).getPredictedCipher() : "AES-256-GCM";
        }
        // IKE activity is not observable outside a capture; the cipher family
        // of the most recent analysis is the honest proxy here.
        int ikeProxy = latestCipher.contains("3DES") || latestCipher.contains("CBC") ? 25 : 8;

        MorphicStateEntity prev = morphicStateRepository != null
            ? morphicStateRepository.findTopByOrderByGeneratedAtDesc().orElse(null)
            : null;
        long previousRotationCount = prev != null ? prev.getRotationCount() : 0;
        String previousConfigId = prev != null ? prev.getConfigId() : null;

        AdaptiveDefenseEngine.MorphicConfig config = AdaptiveDefenseEngine.calculateMorphicRotation(
            meanRisk, latestCipher, ikeProxy, previousRotationCount, previousConfigId);
        // The analysis pipeline's per-analysis flow owns its own row; a
        // scheduled rotation always advances the counter.
        config.rotationCount = previousRotationCount + 1;
        config.rotationIntervalMinutes = (int) intervalMinutes;
        config.dataBasis = "scheduled rotation from " + recent.size()
            + " recent analyses (mean risk " + String.format(Locale.ROOT, "%.1f", meanRisk)
            + "); tiers are real strongSwan proposals";

        persist(config);
        return config;
    }

    private void persist(AdaptiveDefenseEngine.MorphicConfig config) {
        if (morphicStateRepository == null) {
            return;
        }
        MorphicStateEntity e = new MorphicStateEntity();
        e.setConfigId(config.configId);
        e.setIkeProposal(config.currentIkeProposal);
        e.setEspProposal(config.currentEspProposal);
        e.setDhGroup(AdaptiveDefenseEngine.tierDhGroup(config.recommendedTier));
        e.setRotationCount(config.rotationCount);
        e.setExpiresAt(LocalDateTime.now().plusMinutes(intervalMinutes));
        morphicStateRepository.save(e);
    }

    public long getIntervalMinutes() {
        return intervalMinutes;
    }
}
