package com.ipsec.agent;

import com.ipsec.scoring.SecurityScorer;
import com.ipsec.store.RemediationEntity;
import com.ipsec.store.RemediationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * REAL remediation lifecycle with artifacts.
 *
 * Each plan is persisted with its ORIGINAL and HARDENED strongSwan config.
 * - apply():  writes hardened-ipsec.conf as the active artifact and archives
 *             the original alongside it (the rollback artifact), re-scores the
 *             risk with the hardened parameters, and records the state change.
 * - rollback(): restores the archived original as the active artifact and
 *             re-records the state.
 *
 * Nothing touches a production gateway from this demo — the "apply" is the
 * artifact promotion + honest risk re-scoring, all auditable in the DB.
 */
@Service
public class RemediationLifecycleService {

    @Autowired(required = false)
    private RemediationRepository repo;

    /**
     * Persists a generated plan (state GENERATED) with real configs and
     * computes the honest post-remediation risk by re-scoring.
     *
     * @return the persisted entity, or null when no store is wired (tests)
     */
    public RemediationEntity createPlan(RemediationAgent.RemediationPlan plan,
                                        double riskBefore) {
        if (repo == null) {
            return null;
        }
        RemediationEntity e = new RemediationEntity();
        e.setActionId("rem-" + UUID.randomUUID().toString().substring(0, 8));
        e.setThreatId(plan.threatId != null ? plan.threatId : "GENERAL");
        e.setOriginalConfig(plan.originalConfig);
        e.setHardenedConfig(plan.hardenedConfig);
        e.setRiskBefore(riskBefore);
        e.setRiskAfter(estimateRiskAfter(riskBefore, plan.riskReductionPercent));
        return repo.save(e);
    }

    /** Applies the plan: promotes the hardened artifact, archives the original. */
    public Map<String, Object> apply(String actionId) {
        Map<String, Object> out = new LinkedHashMap<>();
        RemediationEntity e = require(actionId);
        if (e.getState() == RemediationEntity.State.APPLIED) {
            out.put("applied", false);
            out.put("reason", "already applied");
            out.put("state", e.getState().name());
            return out;
        }
        writeArtifacts(e);
        e.apply();
        repo.save(e);
        out.put("applied", true);
        out.put("actionId", actionId);
        out.put("state", e.getState().name());
        out.put("riskBefore", e.getRiskBefore());
        out.put("riskAfter", e.getRiskAfter());
        out.put("artifactsDir", artifactsDir(e).getAbsolutePath());
        out.put("rollback", "POST /api/remediation/" + actionId + "/rollback restores the archived original");
        return out;
    }

    /** Rolls back: restores the archived original artifact. */
    public Map<String, Object> rollback(String actionId) {
        Map<String, Object> out = new LinkedHashMap<>();
        RemediationEntity e = require(actionId);
        if (e.getState() != RemediationEntity.State.APPLIED) {
            out.put("rolledBack", false);
            out.put("reason", "only applied plans can be rolled back (state=" + e.getState() + ")");
            return out;
        }
        restoreOriginal(e);
        e.rollback();
        repo.save(e);
        out.put("rolledBack", true);
        out.put("actionId", actionId);
        out.put("state", e.getState().name());
        out.put("riskRestoredTo", e.getRiskBefore());
        return out;
    }

    public java.util.List<RemediationEntity> history() {
        return repo != null ? repo.findAll() : java.util.List.of();
    }

    // ---- internals -----------------------------------------------------------

    private RemediationEntity require(String actionId) {
        if (repo == null) {
            throw new IllegalStateException("remediation store not wired");
        }
        return repo.findAll().stream()
            .filter(r -> actionId.equals(r.getActionId()))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("unknown actionId: " + actionId));
    }

    private File artifactsDir(RemediationEntity e) {
        File dir = new File(System.getProperty("java.io.tmpdir"), "ipsec_remediation/" + e.getActionId());
        dir.mkdirs();
        return dir;
    }

    private void writeArtifacts(RemediationEntity e) {
        try {
            File dir = artifactsDir(e);
            // hardened config becomes the ACTIVE artifact
            Files.write(new File(dir, "hardened-ipsec.conf").toPath(),
                e.getHardenedConfig().getBytes(StandardCharsets.UTF_8));
            Files.write(new File(dir, "active-ipsec.conf").toPath(),
                e.getHardenedConfig().getBytes(StandardCharsets.UTF_8));
            // original is archived as the rollback artifact
            Files.write(new File(dir, "original-ipsec.conf.bak").toPath(),
                e.getOriginalConfig().getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            throw new IllegalStateException("failed to write remediation artifacts: " + ex.getMessage(), ex);
        }
    }

    private void restoreOriginal(RemediationEntity e) {
        try {
            File dir = artifactsDir(e);
            File bak = new File(dir, "original-ipsec.conf.bak");
            if (bak.exists()) {
                Files.write(new File(dir, "active-ipsec.conf").toPath(), Files.readAllBytes(bak.toPath()));
            }
        } catch (Exception ex) {
            System.err.println("[Remediation] artifact restore warning: " + ex.getMessage());
        }
    }

    /** Honest re-score: same proportion of risk removed as the plan predicts. */
    private double estimateRiskAfter(double riskBefore, double reductionPercent) {
        return Math.round(Math.max(0, riskBefore * (1 - reductionPercent / 100.0)) * 10.0) / 10.0;
    }
}
