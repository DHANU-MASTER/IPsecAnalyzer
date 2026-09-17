package com.ipsec.api;

import com.ipsec.agent.RemediationLifecycleService;
import com.ipsec.crypto.CryptoKit;
import com.ipsec.mesh.LedgerService;
import com.ipsec.mesh.MeshNodeService;
import com.ipsec.ml.ModelTrainer;
import com.ipsec.store.MeshEventEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Endpoints exposing the real oracle modules:
 *
 *  - POST /api/mesh/gossip          ingest a peer's HMAC-signed event (public:
 *                                   the HMAC signature is the authentication —
 *                                   forgeries are rejected and never stored)
 *  - GET  /api/mesh/overview        this node + registered peers (JWT required)
 *  - POST /api/mesh/register        register a peer analyzer instance
 *  - GET  /api/ledger/verify        recompute the whole chain (JWT required)
 *  - GET  /api/ledger/blocks        recent sealed blocks
 *  - POST /api/remediation/{id}/apply      promote the hardened artifact
 *  - POST /api/remediation/{id}/rollback   restore the archived original
 *  - GET  /api/remediation          lifecycle history
 *  - POST /api/ml/retrain           re-train the RandomForests now
 *  - GET  /api/ml/status            model files present + health summary
 */
@RestController
public class OracleModuleController {

    @Autowired
    private MeshNodeService meshNodeService;

    @Autowired
    private LedgerService ledgerService;

    @Autowired
    private RemediationLifecycleService remediationLifecycleService;

    @Autowired
    private com.ipsec.oracle.AutonomousDefenseService autonomousDefenseService;

    // ---- autonomous pre-hardening (master prompt Layer 2) -------------------

    /**
     * Applies every generated remediation plan on this node, signs + gossips
     * a mesh event, and seals a ledger block. This is the real operation the
     * dashboard's "Pre-Harden National Mesh Now" button invokes.
     */
    @PostMapping(value = "/api/oracle/pre-harden", produces = "application/json")
    public ResponseEntity<?> preHarden() {
        return ResponseEntity.ok(autonomousDefenseService.preHarden());
    }

    // ---- mesh ----------------------------------------------------------------

    /** Public by design: authentication is the HMAC over the event content. */
    @PostMapping(value = "/api/mesh/gossip", produces = "application/json")
    public ResponseEntity<?> gossip(@RequestBody GossipRequest body) {
        MeshEventEntity incoming = new MeshEventEntity();
        incoming.setEventId(body.eventId);
        incoming.setReporterNodeId(body.reporterNodeId);
        incoming.setThreatType(body.threatType);
        incoming.setDescription(body.description);
        incoming.setSignature(body.signature);
        incoming.setKeyId(body.keyId);
        Map<String, Object> result = meshNodeService.ingestGossip(incoming);
        return ResponseEntity.ok(result);
    }

    public static class GossipRequest {
        public String eventId;
        public String reporterNodeId;
        public String threatType;
        public String description;
        public String signature;
        public String keyId;
    }

    @GetMapping(value = "/api/mesh/overview", produces = "application/json")
    public ResponseEntity<?> meshOverview() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("self", meshNodeService.getNodeId());
        out.put("sector", meshNodeService.getSector());
        out.put("region", meshNodeService.getRegion());
        out.put("keyId", meshNodeService.getKeyId());
        out.put("peerCount", meshNodeService.peerCount());
        out.put("eventCount", meshNodeService.eventCount());
        out.put("nodes", meshNodeService.getMeshOverview());
        out.put("recentEvents", meshNodeService.recentEvents(25));
        return ResponseEntity.ok(out);
    }

    @PostMapping(value = "/api/mesh/register", produces = "application/json")
    public ResponseEntity<?> registerPeer(@RequestBody RegisterRequest body) {
        if (body.nodeId == null || body.nodeId.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "nodeId is required"));
        }
        meshNodeService.registerPeer(body.nodeId, body.sector, body.region, body.baseUrl);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("registered", true);
        out.put("nodeId", body.nodeId);
        out.put("gossipIngest", "POST /api/mesh/gossip with HMAC-SHA256-signed events");
        return ResponseEntity.ok(out);
    }

    public static class RegisterRequest {
        public String nodeId;
        public String sector;
        public String region;
        public String baseUrl;
    }

    // ---- ledger ----------------------------------------------------------------

    @GetMapping(value = "/api/ledger/verify", produces = "application/json")
    public ResponseEntity<?> verifyLedger() {
        return ResponseEntity.ok(ledgerService.verifyChain());
    }

    @GetMapping(value = "/api/ledger/blocks", produces = "application/json")
    public ResponseEntity<?> ledgerBlocks() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("blockCount", ledgerService.blockCount());
        out.put("blocks", ledgerService.recentBlocks(20));
        return ResponseEntity.ok(out);
    }

    // ---- remediation lifecycle --------------------------------------------------

    @PostMapping(value = "/api/remediation/{actionId}/apply", produces = "application/json")
    public ResponseEntity<?> applyRemediation(@PathVariable String actionId) {
        try {
            return ResponseEntity.ok(remediationLifecycleService.apply(actionId));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping(value = "/api/remediation/{actionId}/rollback", produces = "application/json")
    public ResponseEntity<?> rollbackRemediation(@PathVariable String actionId) {
        try {
            return ResponseEntity.ok(remediationLifecycleService.rollback(actionId));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping(value = "/api/remediation", produces = "application/json")
    public ResponseEntity<?> remediationHistory() {
        return ResponseEntity.ok(remediationLifecycleService.history());
    }

    // ---- ML ----------------------------------------------------------------------

    @Autowired
    private AnalysisPipeline analysisPipeline;

    @PostMapping(value = "/api/ml/retrain", produces = "application/json")
    public ResponseEntity<?> retrainModels() {
        ModelTrainer.TrainingReport r = ModelTrainer.retrain("models");
        if (r.error != null) {
            return ResponseEntity.internalServerError().body(r);
        }
        analysisPipeline.reloadModels();
        return ResponseEntity.ok(r);
    }

    @GetMapping(value = "/api/ml/status", produces = "application/json")
    public ResponseEntity<?> mlStatus() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("modelsPresent", ModelTrainer.modelsExist("models"));
        out.put("modelFiles", ModelTrainer.modelsExist("models")
            ? "cipher_classifier.model, tunnel_classifier.model + headers"
            : "none — will train at next startup");
        return ResponseEntity.ok(out);
    }

    /** Convenience integrity endpoint (used by the dashboard supply-chain card). */
    @GetMapping(value = "/api/oracle/hash-check", produces = "application/json")
    public ResponseEntity<?> hashCheck(@RequestParam(defaultValue = "ping") String value) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("value", value);
        out.put("sha256", CryptoKit.sha256Hex(value));
        return ResponseEntity.ok(out);
    }
}
