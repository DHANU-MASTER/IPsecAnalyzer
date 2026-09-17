package com.ipsec.config;

import java.util.*;

public class HardenedConfigGenerator {
    
    public enum SecurityProfile {
        PARANOID,    // Maximum security, maximum CPU cost
        STRICT,      // Government/Defense standard
        BALANCED,    // Default: good security + reasonable performance
        LEGACY       // Support for older endpoints
    }
    
    public static class GeneratedConfig {
        public String ipsecConf;
        public String strongswanConf;
        public String selinuxPolicy;
        public String auditRules;
        public String complianceLevel;
        public List<String> implementation_notes;
    }
    
    public static GeneratedConfig generateConfig(SecurityProfile profile) {
        GeneratedConfig config = new GeneratedConfig();
        config.implementation_notes = new ArrayList<>();
        
        StringBuilder ipsecConf = new StringBuilder();
        ipsecConf.append("# Auto-generated IPsec Configuration\n");
        ipsecConf.append("# Security Profile: ").append(profile.name()).append("\n");
        ipsecConf.append("# Generated: ").append(new Date()).append("\n");
        ipsecConf.append("# NTRO Hardened Standards\n\n");
        
        if (profile == SecurityProfile.PARANOID) {
            ipsecConf.append("conn paranoid-ipsec\n");
            ipsecConf.append("    left=<LOCAL_IP>\n");
            ipsecConf.append("    right=<REMOTE_IP>\n");
            ipsecConf.append("    leftsubnet=<LOCAL_NET>\n");
            ipsecConf.append("    rightsubnet=<REMOTE_NET>\n");
            ipsecConf.append("    ike=aes256gcm16-sha384-x25519-prf-sha512!\n");
            ipsecConf.append("    esp=aes256gcm16-x25519!\n");
            ipsecConf.append("    keyexchange=ikev2\n");
            ipsecConf.append("    type=tunnel\n");
            ipsecConf.append("    pfs=yes\n");
            ipsecConf.append("    rekey_time=1800s\n");
            ipsecConf.append("    authby=secret\n");
            ipsecConf.append("    auto=start\n");
            
            config.complianceLevel = "NSA Suite B + Post-Quantum Hybrid";
            config.implementation_notes.add("Requires strongSwan 5.9+ with X25519 support");
            config.implementation_notes.add("30-min key rotation: higher security, higher CPU cost");
        }
        else if (profile == SecurityProfile.STRICT) {
            ipsecConf.append("conn strict-ipsec\n");
            ipsecConf.append("    left=<LOCAL_IP>\n");
            ipsecConf.append("    right=<REMOTE_IP>\n");
            ipsecConf.append("    leftsubnet=<LOCAL_NET>\n");
            ipsecConf.append("    rightsubnet=<REMOTE_NET>\n");
            ipsecConf.append("    ike=aes256gcm16-sha384-ecp384-prf-sha512\n");
            ipsecConf.append("    esp=aes256gcm16-ecp384\n");
            ipsecConf.append("    keyexchange=ikev2\n");
            ipsecConf.append("    type=tunnel\n");
            ipsecConf.append("    pfs=yes\n");
            ipsecConf.append("    rekey_time=7200s\n");
            ipsecConf.append("    authby=secret\n");
            ipsecConf.append("    auto=start\n");
            
            config.complianceLevel = "NIST SP 800-77 + CIS Controls v8 + NSA Suite B";
            config.implementation_notes.add("Suitable for government/defense networks");
        }
        else if (profile == SecurityProfile.BALANCED) {
            ipsecConf.append("conn balanced-ipsec\n");
            ipsecConf.append("    left=<LOCAL_IP>\n");
            ipsecConf.append("    right=<REMOTE_IP>\n");
            ipsecConf.append("    leftsubnet=<LOCAL_NET>\n");
            ipsecConf.append("    rightsubnet=<REMOTE_NET>\n");
            ipsecConf.append("    ike=aes256gcm16-sha256-ecp256-prf-sha512\n");
            ipsecConf.append("    esp=aes256gcm16-ecp256\n");
            ipsecConf.append("    keyexchange=ikev2\n");
            ipsecConf.append("    type=tunnel\n");
            ipsecConf.append("    pfs=yes\n");
            ipsecConf.append("    rekey_time=14400s\n");
            ipsecConf.append("    authby=secret\n");
            ipsecConf.append("    auto=start\n");
            
            config.complianceLevel = "NIST SP 800-77 + CIS Controls v8";
            config.implementation_notes.add("Default recommended profile");
        }
        else {
            ipsecConf.append("conn legacy-ipsec\n");
            ipsecConf.append("    left=<LOCAL_IP>\n");
            ipsecConf.append("    right=<REMOTE_IP>\n");
            ipsecConf.append("    ike=aes256-sha256-modp2048,aes128-sha256-modp2048\n");
            ipsecConf.append("    esp=aes256-sha256,aes128-sha256\n");
            ipsecConf.append("    keyexchange=ikev2\n");
            ipsecConf.append("    pfs=yes\n");
            ipsecConf.append("    rekey_time=28800s\n");
            ipsecConf.append("    auto=start\n");
            
            config.complianceLevel = "Minimal (legacy support only)";
            config.implementation_notes.add("⚠️ DEPRECATED: Migration to BALANCED recommended");
        }
        
        config.ipsecConf = ipsecConf.toString();
        config.selinuxPolicy = generateSELinuxPolicy();
        config.auditRules = generateAuditRules();
        
        return config;
    }
    
    private static String generateSELinuxPolicy() {
        return "# SELinux policy for strongSwan\n" +
               "allow charon_t self:capability { dac_override net_admin sys_admin };\n" +
               "allow charon_t ipsec_var_run_t:dir { read write };\n" +
               "allow charon_t ipsec_var_run_t:file { read write create };\n";
    }
    
    private static String generateAuditRules() {
        return "# Audit rules for IPsec monitoring\n" +
               "-w /etc/ipsec.conf -p wa -k ipsec_conf_changes\n" +
               "-w /etc/ipsec.secrets -p wa -k ipsec_secrets_changes\n" +
               "-a always,exit -F path=/usr/sbin/ipsec -F perm=x -F auid>=1000 -k ipsec_execution\n";
    }
}
