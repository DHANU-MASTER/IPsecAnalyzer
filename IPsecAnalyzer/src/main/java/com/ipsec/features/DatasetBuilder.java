package com.ipsec.features;

import com.ipsec.capture.PcapReader;
import org.pcap4j.packet.Packet;

import java.io.*;
import java.util.*;

public class DatasetBuilder {
    
    public static class TrainingInstance {
        public String pcapFile;
        public FeatureExtractor.PacketFeatures features;
        public String tunnelMode;      // "Tunnel" or "Transport"
        public String cipherSuite;     // "AES-128", "AES-256-GCM"
        public String trafficType;     // "ICMP", "Web", "VoIP", "Mixed"
        
        @Override
        public String toString() {
            return String.format("%s,%.2f,%.2f,%.2f,%.2f,%d,%d,%d,%s,%s,%s",
                pcapFile, features.avgPacketSize, features.stdPacketSize,
                features.avgInterArrivalTime, features.stdInterArrivalTime,
                features.ikeNegotiationCount, features.espPacketCount, features.sessionDuration,
                tunnelMode, cipherSuite, trafficType);
        }
    }
    
    public static void buildTrainingData(String datasetDir, String outputCsv) throws Exception {
        List<TrainingInstance> instances = new ArrayList<>();
        
        File dir = new File(datasetDir);
        if (!dir.exists() || !dir.isDirectory()) {
            return;
        }
        
        File[] files = dir.listFiles((d, name) -> name.endsWith(".pcap"));
        if (files == null) return;
        
        for (File file : files) {
            String[] parts = file.getName().replace(".pcap", "").split("_");
            String config = parts[0];
            String traffic = parts.length > 1 ? parts[1] : "mixed";
            
            List<PcapReader.TimestampedPacket> packets = PcapReader.readPcapWithTimestamps(file.getAbsolutePath());
            FeatureExtractor.PacketFeatures features = FeatureExtractor.extract(packets);
            
            TrainingInstance instance = new TrainingInstance();
            instance.pcapFile = file.getName();
            instance.features = features;
            instance.tunnelMode = config.contains("tunnel") ? "Tunnel" : "Transport";
            instance.cipherSuite = extractCipher(config);
            instance.trafficType = capitalizeFirst(traffic);
            
            instances.add(instance);
        }
        
        try (PrintWriter writer = new PrintWriter(outputCsv)) {
            writer.println("PcapFile,AvgPktSize,StdPktSize,AvgIAT,StdIAT,IKECount," +
                          "ESPCount,Duration,TunnelMode,Cipher,TrafficType");
            for (TrainingInstance inst : instances) {
                writer.println(inst.toString());
            }
        }
    }
    
    private static String extractCipher(String config) {
        if (config.contains("aes128")) return "AES-128";
        if (config.contains("aes256-gcm")) return "AES-256-GCM";
        return "Unknown";
    }
    
    private static String capitalizeFirst(String s) {
        if (s == null || s.isEmpty()) return "Unknown";
        return s.substring(0, 1).toUpperCase() + s.substring(1);
    }
}
