package com.ipsec.agent;

import com.ipsec.scoring.SecurityScorer;
import java.util.*;

public class RemediationAgent {
    
    public static class RemediationPlan {
        public String threatId;
        public String originalConfig;
        public String hardenedConfig;
        public double riskReductionPercent;
        public List<String> remediationSteps;
        public boolean canAutoApply;
        public String downtime;
        public String rollbackStrategy;
        /** Populated when the plan is persisted (null when no store is wired). */
        public String actionId;
        
        @Override
        public String toString() {
            return String.format("Remediation: %s | Risk reduction: %.1f%% | Auto-apply: %s",
                threatId, riskReductionPercent, canAutoApply);
        }
    }
    
    public static List<RemediationPlan> generateRemediationPlans(
            SecurityScorer.SecurityAssessment assessment,
            String currentIkeCfg,
            String currentEspCfg) {
        
        List<RemediationPlan> plans = new ArrayList<>();
        
        if (assessment == null || assessment.vulnerabilities == null) {
            return plans;
        }
        
        for (String vulnerability : assessment.vulnerabilities) {
            RemediationPlan plan = new RemediationPlan();
            plan.originalConfig = (currentIkeCfg != null ? currentIkeCfg : "IKE default") + " | " + 
                                 (currentEspCfg != null ? currentEspCfg : "ESP default");
            plan.remediationSteps = new ArrayList<>();
            
            if (vulnerability.toLowerCase().contains("weak") && vulnerability.toLowerCase().contains("cipher")) {
                plan.threatId = "WEAK_CIPHER";
                plan.hardenedConfig = "ike=aes256gcm16-sha384-ecp384 ! esp=aes256gcm16-ecp384";
                plan.riskReductionPercent = 75.0;
                plan.remediationSteps.add("Backup current IKE config");
                plan.remediationSteps.add("Update ipsec.conf with AES-256-GCM");
                plan.remediationSteps.add("Restart strongSwan gracefully (drain connections)");
                plan.remediationSteps.add("Verify new tunnel parameters");
                plan.canAutoApply = true;
                plan.downtime = "< 2 seconds (connection re-negotiation)";
                plan.rollbackStrategy = "Restore previous config + reload";
            }
            else if (vulnerability.contains("PFS")) {
                plan.threatId = "PFS_DISABLED";
                plan.hardenedConfig = "ipsec.conf: pfs=yes";
                plan.riskReductionPercent = 60.0;
                plan.remediationSteps.add("Edit /etc/ipsec.conf");
                plan.remediationSteps.add("Add 'pfs=yes' to conn block");
                plan.remediationSteps.add("ipsec reload (no tunnel restart required)");
                plan.canAutoApply = true;
                plan.downtime = "0 seconds (config reload only)";
                plan.rollbackStrategy = "Remove 'pfs=yes' line";
            }
            else if (vulnerability.contains("DH")) {
                plan.threatId = "WEAK_DH_GROUP";
                plan.hardenedConfig = "Use RFC 7748 (Curve25519/448) or RFC 3394 (DH Group 20+)";
                plan.riskReductionPercent = 70.0;
                plan.remediationSteps.add("Check strongSwan version support for RFC 7748");
                plan.remediationSteps.add("Upgrade strongSwan if needed");
                plan.remediationSteps.add("Update ike= parameter with new DH group");
                plan.remediationSteps.add("Coordinate with peer gateway");
                plan.canAutoApply = false;
                plan.downtime = "Requires maintenance window";
                plan.rollbackStrategy = "Revert ike= parameter";
            }
            else if (vulnerability.contains("Key Lifetime")) {
                plan.threatId = "LONG_KEY_LIFETIME";
                plan.hardenedConfig = "lifetime=3600s (1 hour) / lifetime=14400s (4 hours)";
                plan.riskReductionPercent = 55.0;
                plan.remediationSteps.add("Edit /etc/ipsec.conf");
                plan.remediationSteps.add("Set lifetimeike=3600 and lifetimeipsec=7200");
                plan.remediationSteps.add("ipsec reload");
                plan.canAutoApply = true;
                plan.downtime = "0 seconds";
                plan.rollbackStrategy = "Revert lifetime settings";
            }
            else if (vulnerability.contains("Transport")) {
                plan.threatId = "TRANSPORT_MODE";
                plan.hardenedConfig = "type=tunnel (instead of type=transport)";
                plan.riskReductionPercent = 40.0;
                plan.remediationSteps.add("Requires change in tunnel type");
                plan.remediationSteps.add("May need IP routing adjustments");
                plan.remediationSteps.add("Coordinate with endpoints");
                plan.canAutoApply = false;
                plan.downtime = "Requires planned migration";
                plan.rollbackStrategy = "Revert to transport mode";
            }
            else {
                plan.threatId = "GENERAL_SECURITY";
                plan.hardenedConfig = "ike=aes256gcm16-sha384-ecp384 ! esp=aes256gcm16";
                plan.riskReductionPercent = 30.0;
                plan.remediationSteps.add("Review security baseline policy");
                plan.remediationSteps.add("Apply NIST SP 800-77 guidelines");
                plan.canAutoApply = true;
                plan.downtime = "0 seconds";
                plan.rollbackStrategy = "Revert baseline settings";
            }
            
            plans.add(plan);
        }
        
        return plans;
    }
    
    public static class RemediationSimulation {
        public String planId;
        public boolean simulated_success;
        public String before_risk_score;
        public String after_risk_score;
        public List<String> potential_side_effects;
        public String predicted_impact;
        
        public RemediationSimulation() {
            this.potential_side_effects = new ArrayList<>();
        }
    }
    
    public static RemediationSimulation simulateRemediation(
            RemediationPlan plan,
            SecurityScorer.SecurityAssessment currentAssessment) {
        
        RemediationSimulation sim = new RemediationSimulation();
        sim.planId = plan.threatId;
        sim.before_risk_score = String.format("%.1f", currentAssessment.overallRiskScore);
        
        double simulated_risk = currentAssessment.overallRiskScore * (1 - plan.riskReductionPercent / 100.0);
        sim.after_risk_score = String.format("%.1f", simulated_risk);
        sim.simulated_success = true;
        
        if ("WEAK_CIPHER".equals(plan.threatId)) {
            sim.potential_side_effects.add("Short tunnel re-negotiation (< 2 sec)");
            sim.potential_side_effects.add("Increased CPU usage during rekey (temporary)");
            sim.potential_side_effects.add("Older clients may fail to connect");
        } else if ("WEAK_DH_GROUP".equals(plan.threatId)) {
            sim.potential_side_effects.add("Requires peer gateway update");
            sim.potential_side_effects.add("Downtime during migration");
            sim.potential_side_effects.add("Performance impact (CPU for new DH groups)");
        }
        
        sim.predicted_impact = "Risk score: " + sim.before_risk_score + " → " + sim.after_risk_score +
                              " | Status: Risk Level Drop ✓";
        
        return sim;
    }
}
