package com.ipsec.features;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import com.ipsec.capture.PcapReader.TimestampedPacket;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;

import java.util.List;

public class FeatureExtractor {

    public static class PacketFeatures {
        public double avgPacketSize;
        public double stdPacketSize;
        public double avgInterArrivalTime;  // milliseconds (real capture time)
        public double stdInterArrivalTime;  // milliseconds (real capture time)
        public int ikeNegotiationCount;
        public int espPacketCount;
        public int ahPacketCount;
        public double packetSizeVariance;
        public long sessionDuration;  // seconds, from real first/last packet timestamps
        public int ipsecProtocol;  // 50=ESP, 51=AH
        public String predominantPort;

        @Override
        public String toString() {
            return String.format(
                "AvgPktSize=%.2f, StdPktSize=%.2f, AvgIAT=%.2f ms, StdIAT=%.2f ms, " +
                "IKE=%d, ESP=%d, AH=%d, Protocol=%d, Duration=%ds",
                avgPacketSize, stdPacketSize, avgInterArrivalTime, stdInterArrivalTime,
                ikeNegotiationCount, espPacketCount, ahPacketCount, ipsecProtocol, sessionDuration
            );
        }
    }

    /**
     * Extract features from packets with real capture timestamps.
     * Inter-arrival times are computed from pcap timestamps, not wall-clock,
     * so re-analyzing the same file yields identical features.
     */
    public static PacketFeatures extract(List<TimestampedPacket> packets) {
        PacketFeatures features = new PacketFeatures();

        DescriptiveStatistics sizeStats = new DescriptiveStatistics();
        DescriptiveStatistics iatStats = new DescriptiveStatistics();
        long firstTs = -1;
        long prevTs = -1;
        int espCount = 0;
        int ikeCount = 0;
        int ahCount = 0;

        if (packets != null) {
            for (TimestampedPacket tp : packets) {
                if (tp == null || tp.packet == null) continue;
                Packet pkt = tp.packet;
                long ts = tp.timestampMillis;

                sizeStats.addValue(pkt.length());

                if (firstTs < 0) {
                    firstTs = ts;
                } else if (ts > prevTs) {
                    iatStats.addValue(ts - prevTs);
                }
                prevTs = ts;

                if (isIKEPacket(pkt)) ikeCount++;
                if (isESPPacket(pkt)) espCount++;
                if (isAHPacket(pkt)) ahCount++;
            }
        }

        features.avgPacketSize = sizeStats.getN() > 0 ? sizeStats.getMean() : 0;
        features.stdPacketSize = sizeStats.getN() >= 2 ? sizeStats.getStandardDeviation() : 0;
        features.packetSizeVariance = sizeStats.getN() >= 2 ? sizeStats.getVariance() : 0;
        features.ikeNegotiationCount = ikeCount;
        features.espPacketCount = espCount;
        features.ahPacketCount = ahCount;
        // 50 = ESP, 51 = AH, 0 = neither observed
        features.ipsecProtocol = espCount > 0 ? 50 : (ahCount > 0 ? 51 : 0);

        if (iatStats.getN() > 0) {
            features.avgInterArrivalTime = iatStats.getMean();
            features.stdInterArrivalTime = iatStats.getN() >= 2 ? iatStats.getStandardDeviation() : 0;
        }

        if (firstTs > 0 && prevTs > firstTs) {
            features.sessionDuration = (prevTs - firstTs) / 1000;
        }

        return features;
    }

    public static boolean isIKEPacket(Packet pkt) {
        if (pkt == null) return false;
        IpV4Packet ipv4 = pkt.get(IpV4Packet.class);
        if (ipv4 != null) {
            UdpPacket udp = ipv4.get(UdpPacket.class);
            if (udp != null && udp.getHeader() != null) {
                int dstPort = udp.getHeader().getDstPort() != null
                    ? udp.getHeader().getDstPort().valueAsInt() : -1;
                int srcPort = udp.getHeader().getSrcPort() != null
                    ? udp.getHeader().getSrcPort().valueAsInt() : -1;
                return dstPort == 500 || dstPort == 4500 || srcPort == 500 || srcPort == 4500;
            }
        }
        return false;
    }

    public static boolean isESPPacket(Packet pkt) {
        if (pkt == null) return false;
        IpV4Packet ipv4 = pkt.get(IpV4Packet.class);
        if (ipv4 != null && ipv4.getHeader() != null && ipv4.getHeader().getProtocol() != null) {
            return ipv4.getHeader().getProtocol().value() == 50;
        }
        return false;
    }

    public static boolean isAHPacket(Packet pkt) {
        if (pkt == null) return false;
        IpV4Packet ipv4 = pkt.get(IpV4Packet.class);
        if (ipv4 != null && ipv4.getHeader() != null && ipv4.getHeader().getProtocol() != null) {
            return ipv4.getHeader().getProtocol().value() == 51;
        }
        return false;
    }
}
