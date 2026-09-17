package com.ipsec.capture;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.util.*;

/**
 * Reads pcap files while preserving capture timestamps so that inter-arrival
 * times can be computed from real packet timing instead of wall-clock time.
 */
public class PcapReader {

    /** A packet paired with its capture timestamp in epoch millis. */
    public static class TimestampedPacket {
        public final Packet packet;
        public final long timestampMillis;

        public TimestampedPacket(Packet packet, long timestampMillis) {
            this.packet = packet;
            this.timestampMillis = timestampMillis;
        }
    }

    public static List<Packet> readPcap(String filePath) throws Exception {
        List<Packet> packets = new ArrayList<>();
        for (TimestampedPacket tp : readPcapWithTimestamps(filePath)) {
            packets.add(tp.packet);
        }
        return packets;
    }

    public static List<TimestampedPacket> readPcapWithTimestamps(String filePath) throws Exception {
        final List<TimestampedPacket> packets = new ArrayList<>();
        PcapHandle handle = null;

        try {
            handle = Pcaps.openOffline(filePath);
            final PcapHandle h = handle;

            handle.loop(-1, new PacketListener() {
                @Override
                public void gotPacket(Packet tp) {
                    if (tp != null) {
                        long tsMillis = h.getTimestamp().getTime();
                        packets.add(new TimestampedPacket(tp, tsMillis));

                        if (packets.size() % 10000 == 0) {
                            System.out.println("[PcapReader] parsed " + packets.size() + " packets...");
                        }
                        // Safety valve: refuse absurd captures instead of exhausting heap
                        if (packets.size() >= 2_000_000) {
                            throw new IllegalStateException("Capture too large (> 2,000,000 packets)");
                        }
                    }
                }
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            if (handle != null) {
                handle.close();
            }
        }

        return packets;
    }
}
