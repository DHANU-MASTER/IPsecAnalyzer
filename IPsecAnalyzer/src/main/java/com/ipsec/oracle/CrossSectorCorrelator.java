package com.ipsec.oracle;

import com.ipsec.store.MeshEventEntity;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * REAL cross-sector correlation.
 *
 * Sectors are the mesh nodes registered in THIS deployment (each node names
 * its sector). The correlator:
 *   1. Pulls real threat events from the mesh event store.
 *   2. Clusters them by threat signature across sectors in a 24h window.
 *   3. Emits per-sector status (UNDER_ATTACK / MONITORING / SAFE) derived
 *      strictly from that sector's actual event counts.
 *   4. Counts coordinated probes: distinct sectors reporting the same threat
 *      type recently — a genuine multi-sector pattern, or none.
 */
public class CrossSectorCorrelator {

    public static class SectorStatus {
        public String sectorName;
        public String alertLevel;   // UNDER_ATTACK, MONITORING, SAFE
        public String activeThreatSignature;
        public String lastEventTimestamp;
        public int eventsLast24h;
    }

    public static class CrossSectorAlert {
        public String incidentId;
        public String primaryTargetSector;
        public String threatActor;
        public String correlatedAttacksCount;
        public List<SectorStatus> nationalSectors = new ArrayList<>();
        public String recommendedGovernmentAction;
        public String dataBasis;
    }

    /** Node-to-sector mapping discovered from live mesh registration. */
    public interface SectorResolver {
        /** @return sector name for a node id, or null if unknown. */
        String sectorOf(String nodeId);
    }

    /**
     * @param currentThreatType threat signature produced by THIS analysis
     * @param ownSector         sector name of this instance
     * @param events            real persisted mesh events (may be empty)
     * @param sectorResolver    maps node ids to sectors (from mesh registry)
     */
    public static CrossSectorAlert analyzeCrossSectorCorrelation(String currentThreatType,
                                                                 String ownSector,
                                                                 List<MeshEventEntity> events,
                                                                 SectorResolver sectorResolver) {
        CrossSectorAlert alert = new CrossSectorAlert();
        alert.incidentId = "XSECTOR-" + Long.toHexString(System.currentTimeMillis());

        LocalDateTime since = LocalDateTime.now().minusHours(24);
        List<MeshEventEntity> recent = new ArrayList<>();
        if (events != null) {
            for (MeshEventEntity e : events) {
                if (e.getCreatedAt() != null && e.getCreatedAt().isAfter(since)) {
                    recent.add(e);
                }
            }
        }

        // ---- group events by sector ---------------------------------------
        Map<String, List<MeshEventEntity>> bySector = new LinkedHashMap<>();
        for (MeshEventEntity e : recent) {
            String sector = sectorResolver != null ? sectorResolver.sectorOf(e.getReporterNodeId()) : null;
            if (sector == null) {
                sector = "Unassigned";
            }
            bySector.computeIfAbsent(sector, k -> new ArrayList<>()).add(e);
        }
        if (ownSector != null) {
            bySector.computeIfAbsent(ownSector, k -> new ArrayList<>()); // always show own sector
        }

        // ---- per-sector status from real event counts ---------------------
        String primarySector = ownSector;
        int primaryCount = -1;
        for (Map.Entry<String, List<MeshEventEntity>> entry : bySector.entrySet()) {
            SectorStatus st = new SectorStatus();
            st.sectorName = entry.getKey();
            st.eventsLast24h = entry.getValue().size();
            MeshEventEntity last = entry.getValue().stream()
                .max((a, b) -> a.getCreatedAt().compareTo(b.getCreatedAt())).orElse(null);
            st.lastEventTimestamp = last != null ? last.getCreatedAt().toString() : "none in 24h";
            st.activeThreatSignature = last != null ? last.getThreatType() : "None";

            if (st.eventsLast24h >= 3) {
                st.alertLevel = "UNDER_ATTACK";
            } else if (st.eventsLast24h >= 1) {
                st.alertLevel = "MONITORING";
            } else {
                st.alertLevel = "SAFE";
            }
            alert.nationalSectors.add(st);

            if (st.eventsLast24h > primaryCount) {
                primaryCount = st.eventsLast24h;
                primarySector = st.sectorName;
            }
        }
        alert.primaryTargetSector = primarySector != null ? primarySector : "None (no events)";

        // ---- coordinated pattern: same threat type across >= 2 sectors ----
        Map<String, java.util.Set<String>> threatToSectors = new LinkedHashMap<>();
        for (MeshEventEntity e : recent) {
            String sector = sectorResolver != null ? sectorResolver.sectorOf(e.getReporterNodeId()) : null;
            threatToSectors.computeIfAbsent(e.getThreatType(), k -> new java.util.HashSet<>())
                .add(sector != null ? sector : "Unassigned");
        }
        long coordinated = threatToSectors.values().stream().filter(s -> s.size() >= 2).count();
        if (coordinated > 0) {
            alert.correlatedAttacksCount = coordinated + " coordinated cross-sector pattern(s) in the last 24h";
        } else {
            alert.correlatedAttacksCount = "No cross-sector pattern — events are sector-local";
        }

        // ---- threat actor: described by behaviour, not invented name ------
        alert.threatActor = recent.isEmpty()
            ? "No adversary observed in the mesh"
            : "Activity pattern: " + recent.stream().map(MeshEventEntity::getThreatType)
                .distinct().sorted().limit(3).reduce((a, b) -> a + ", " + b).orElse("n/a");

        // ---- recommended action derives from the real state ---------------
        if (coordinated > 0) {
            alert.recommendedGovernmentAction = "Multi-sector pattern detected: raise posture across sectors "
                + "sharing the correlated signature and share the hardening profile mesh-wide";
        } else if (primaryCount >= 3) {
            alert.recommendedGovernmentAction = "Concentrated activity in " + primarySector
                + ": isolate affected nodes and pre-harden peer sectors with the same gateway stack";
        } else if (currentThreatType != null) {
            alert.recommendedGovernmentAction = "Record the current signature in the collective ledger "
                + "so peer sectors can pre-harden on receipt";
        } else {
            alert.recommendedGovernmentAction = "No action required — mesh is quiet";
        }

        alert.dataBasis = recent.size() + " real mesh event(s) in the last 24h across "
            + bySector.size() + " sector(s); correlation computed over the event store";
        return alert;
    }
}
