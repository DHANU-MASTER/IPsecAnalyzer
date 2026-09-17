package com.ipsec.oracle;

import com.ipsec.agent.RemediationLifecycleService;
import com.ipsec.mesh.LedgerService;
import com.ipsec.mesh.MeshNodeService;
import com.ipsec.store.MeshEventEntity;
import com.ipsec.store.RemediationEntity;
import com.ipsec.store.RemediationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * REAL autonomous pre-hardening orchestration (master prompt Layer 2).
 *
 * Backs the dashboard's "Pre-Harden National Mesh Now" button with an actual
 * operation instead of a JavaScript alert:
 *
 *  1. Every generated remediation plan from recent analyses is applied for
 *     real through {@link RemediationLifecycleService#apply} — the hardened
 *     strongSwan config is promoted to the active artifact and the original
 *     is archived for rollback (artifact-level, not live devices; the
 *     response says so explicitly).
 *  2. A MESH_PRE_HARDENING_EXECUTED event is signed (HMAC) and gossiped to
 *     all registered peer nodes so their sectors can pre-harden too.
 *  3. The whole action is sealed into the collective-memory ledger.
 *
 * Every result carries a {@code dataBasis} provenance label.
 */
@Service
public class AutonomousDefenseService {

    private final RemediationRepository remediationRepository;
    private final RemediationLifecycleService remediationLifecycleService;
    private final MeshNodeService meshNodeService;
    private final LedgerService ledgerService;

    @Autowired
    public AutonomousDefenseService(RemediationRepository remediationRepository,
                                    RemediationLifecycleService remediationLifecycleService,
                                    MeshNodeService meshNodeService,
                                    LedgerService ledgerService) {
        this.remediationRepository = remediationRepository;
        this.remediationLifecycleService = remediationLifecycleService;
        this.meshNodeService = meshNodeService;
        this.ledgerService = ledgerService;
    }

    public Map<String, Object> preHarden() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("operation", "AUTONOMOUS_PRE_HARDENING");
        out.put("scope", "generated remediation plans on this node + signed mesh gossip to peers");

        // ---- 1. Apply every pending (GENERATED) plan for real ----------------
        List<Map<String, Object>> applied = new ArrayList<>();
        int alreadyApplied = 0;
        int failed = 0;
        if (remediationRepository != null) {
            List<RemediationEntity> pending = remediationRepository.findAll().stream()
                .filter(r -> r.getState() == RemediationEntity.State.GENERATED)
                .toList();
            for (RemediationEntity plan : pending) {
                try {
                    applied.add(remediationLifecycleService.apply(plan.getActionId()));
                } catch (Exception ex) {
                    failed++;
                    System.err.println("[PreHarden] apply " + plan.getActionId()
                        + " failed: " + ex.getMessage());
                }
            }
            alreadyApplied = (int) remediationRepository.findAll().stream()
                .filter(r -> r.getState() == RemediationEntity.State.APPLIED
                    || r.getState() == RemediationEntity.State.ROLLED_BACK)
                .count();
        }

        // ---- 2. Signed mesh event so peers pre-harden their sectors ----------
        MeshEventEntity meshEvent = null;
        try {
            meshEvent = meshNodeService.recordThreatEvent("PRE_HARDENING_EXECUTED",
                "node " + meshNodeService.getNodeId() + " applied " + applied.size()
                    + " hardened config(s); peer sectors should pre-harden matching gateways");
        } catch (Exception ex) {
            System.err.println("[PreHarden] mesh gossip failed: " + ex.getMessage());
        }

        // ---- 3. Seal the operation into the collective-memory ledger ---------
        List<LedgerService.SealedEvent> events = new ArrayList<>();
        events.add(new LedgerService.SealedEvent("PRE_HARDENING_EXECUTED",
            "appliedPlans=" + applied.size() + " failed=" + failed
                + " nodeId=" + meshNodeService.getNodeId()));
        if (meshEvent != null) {
            events.add(new LedgerService.SealedEvent("MESH_EVENT_SIGNED",
                "eventId=" + meshEvent.getEventId() + " type=PRE_HARDENING_EXECUTED"));
        }
        Object block = null;
        try {
            block = ledgerService.seal(events);
        } catch (Exception ex) {
            System.err.println("[PreHarden] ledger sealing failed: " + ex.getMessage());
        }

        out.put("appliedPlans", applied);
        out.put("appliedCount", applied.size());
        out.put("alreadyAppliedCount", alreadyApplied);
        out.put("failedCount", failed);
        out.put("meshGossip", meshEvent != null
            ? Map.of("eventId", meshEvent.getEventId(),
                     "signed", true,
                     "peersNotified", meshNodeService.peerCount())
            : Map.of("signed", false, "reason", "mesh store unavailable"));
        out.put("ledgerBlock", block != null ? block : Map.of("sealed", false));
        out.put("boundary", "Artifact-level orchestration: hardened configs are promoted in the "
            + "remediation artifact store and archived for rollback. No live VPN device is "
            + "reconfigured from this demo deployment.");
        out.put("dataBasis", "real apply operations over persisted remediation plans, "
            + "HMAC-signed mesh event, and a sealed ledger block");
        return out;
    }
}
