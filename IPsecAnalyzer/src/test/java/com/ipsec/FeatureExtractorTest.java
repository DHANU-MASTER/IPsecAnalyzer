package com.ipsec;

import com.ipsec.capture.PcapReader.TimestampedPacket;
import com.ipsec.features.FeatureExtractor;
import com.ipsec.support.PcapFixtures;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FeatureExtractorTest {

    private static final long START = 1_700_000_000_000L;

    @Test
    @DisplayName("Counts IKE packets (both directions, ports 500/4500)")
    void countsIkePackets() {
        List<PcapFixtures.Record> records = PcapFixtures.ipsecSession(0, 50, START);

        FeatureExtractor.PacketFeatures features =
            FeatureExtractor.extract(PcapFixtures.toTimestampedPackets(records));

        assertEquals(4, features.ikeNegotiationCount,
            "two IKE_SA_INIT + two IKE_AUTH packets expected");
        assertEquals(0, features.espPacketCount);
    }

    @Test
    @DisplayName("Counts ESP packets and reports protocol 50")
    void countsEspPackets() {
        List<PcapFixtures.Record> records = PcapFixtures.ipsecSession(30, 50, START);

        FeatureExtractor.PacketFeatures features =
            FeatureExtractor.extract(PcapFixtures.toTimestampedPackets(records));

        assertEquals(30, features.espPacketCount);
        assertEquals(0, features.ahPacketCount);
        assertEquals(50, features.ipsecProtocol);
    }

    @Test
    @DisplayName("Counts AH packets and reports protocol 51")
    void countsAhPackets() {
        List<PcapFixtures.Record> records = PcapFixtures.ipsecSession(12, 51, START);

        FeatureExtractor.PacketFeatures features =
            FeatureExtractor.extract(PcapFixtures.toTimestampedPackets(records));

        assertEquals(0, features.espPacketCount);
        assertEquals(12, features.ahPacketCount);
        assertEquals(51, features.ipsecProtocol);
    }

    @Test
    @DisplayName("Inter-arrival times come from capture timestamps, not wall clock")
    void interArrivalTimesUseCaptureTimestamps() {
        // Three ESP packets 100 ms apart, plus the IKE prefix
        long base = START;
        List<PcapFixtures.Record> records = List.of(
            new PcapFixtures.Record(base, PcapFixtures.udpPacket("10.0.1.2", "10.0.1.3", 500, 500, 200)),
            new PcapFixtures.Record(base + 100, PcapFixtures.ipsecPacket("10.0.1.2", "10.0.1.3", 50, 200)),
            new PcapFixtures.Record(base + 200, PcapFixtures.ipsecPacket("10.0.1.2", "10.0.1.3", 50, 200)),
            new PcapFixtures.Record(base + 300, PcapFixtures.ipsecPacket("10.0.1.2", "10.0.1.3", 50, 200))
        );

        FeatureExtractor.PacketFeatures features =
            FeatureExtractor.extract(PcapFixtures.toTimestampedPackets(records));

        assertEquals(100.0, features.avgInterArrivalTime, 0.001,
            "average inter-arrival should be exactly 100 ms");
        assertEquals(0.0, features.stdInterArrivalTime, 0.001);
        assertEquals(0, features.sessionDuration, "duration under one second");
    }

    @Test
    @DisplayName("Session duration uses first and last capture timestamps")
    void sessionDurationFromTimestamps() {
        List<PcapFixtures.Record> records = List.of(
            new PcapFixtures.Record(START, PcapFixtures.udpPacket("10.0.1.2", "10.0.1.3", 500, 500, 100)),
            new PcapFixtures.Record(START + 5_000, PcapFixtures.ipsecPacket("10.0.1.2", "10.0.1.3", 50, 100)),
            new PcapFixtures.Record(START + 12_500, PcapFixtures.ipsecPacket("10.0.1.2", "10.0.1.3", 50, 100))
        );

        FeatureExtractor.PacketFeatures features =
            FeatureExtractor.extract(PcapFixtures.toTimestampedPackets(records));

        assertEquals(12, features.sessionDuration, "12.5s of capture should report 12s");
    }

    @Test
    @DisplayName("Empty captures produce zeroed features instead of failing")
    void handlesEmptyCapture() {
        FeatureExtractor.PacketFeatures features = FeatureExtractor.extract(List.<TimestampedPacket>of());

        assertEquals(0.0, features.avgPacketSize);
        assertEquals(0, features.ikeNegotiationCount);
        assertEquals(0, features.espPacketCount);
        assertEquals(0, features.ipsecProtocol);
        assertEquals(0, features.sessionDuration);
    }

    @Test
    @DisplayName("Packet size statistics are computed from all packets")
    void packetSizeStatistics() {
        List<PcapFixtures.Record> records = PcapFixtures.ipsecSession(20, 50, START);

        FeatureExtractor.PacketFeatures features =
            FeatureExtractor.extract(PcapFixtures.toTimestampedPackets(records));

        assertTrue(features.avgPacketSize > 0, "average size should be positive");
        assertTrue(features.stdPacketSize > 0, "mixed traffic should have variance");
        assertTrue(features.packetSizeVariance > 0);
    }

    @Test
    @DisplayName("Only IPv4 UDP 500/4500 traffic is treated as IKE")
    void ignoresNonIkeUdp() {
        List<PcapFixtures.Record> records = List.of(
            new PcapFixtures.Record(START, PcapFixtures.udpPacket("10.0.1.2", "10.0.1.3", 12345, 8080, 100)),
            new PcapFixtures.Record(START + 5, PcapFixtures.udpPacket("10.0.1.2", "10.0.1.3", 500, 500, 100))
        );

        FeatureExtractor.PacketFeatures features =
            FeatureExtractor.extract(PcapFixtures.toTimestampedPackets(records));

        assertEquals(1, features.ikeNegotiationCount);
    }
}
