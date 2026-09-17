package com.ipsec.support;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import com.ipsec.capture.PcapReader.TimestampedPacket;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Builds synthetic but structurally valid Ethernet/IPv4 captures for tests,
 * without requiring the native libpcap library.
 */
public final class PcapFixtures {

    public static final String CLIENT_IP = "10.0.1.2";
    public static final String SERVER_IP = "10.0.1.3";

    private static final byte[] DST_MAC = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    private static final byte[] SRC_MAC = {0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB};

    private PcapFixtures() {
    }

    /** Parses raw Ethernet bytes into a pcap4j packet (no native library needed). */
    public static Packet parseEthernet(byte[] raw) {
        try {
            return EthernetPacket.newPacket(raw, 0, raw.length);
        } catch (IllegalRawDataException e) {
            throw new IllegalStateException("fixture produced an unparsable frame", e);
        }
    }

    /** Builds a UDP packet (used for IKE on ports 500/4500). */
    public static byte[] udpPacket(String src, String dst, int srcPort, int dstPort, int payloadSize) {
        byte[] payload = new byte[payloadSize];
        new Random(payloadSize).nextBytes(payload);

        byte[] udp = new byte[8 + payload.length];
        udp[0] = (byte) (srcPort >> 8);
        udp[1] = (byte) srcPort;
        udp[2] = (byte) (dstPort >> 8);
        udp[3] = (byte) dstPort;
        int udpLength = udp.length;
        udp[4] = (byte) (udpLength >> 8);
        udp[5] = (byte) udpLength;
        System.arraycopy(payload, 0, udp, 8, payload.length);

        return ethernet(ipv4(udp, src, dst, (byte) 17));
    }

    /** Builds an ESP (protocol 50) or AH (protocol 51) packet. */
    public static byte[] ipsecPacket(String src, String dst, int protocol, int payloadSize) {
        byte[] payload = new byte[payloadSize + 12];   // ESP/AH header overhead
        new Random(payloadSize).nextBytes(payload);
        return ethernet(ipv4(payload, src, dst, (byte) protocol));
    }

    private static byte[] ipv4(byte[] payload, String src, String dst, byte protocol) {
        byte[] header = new byte[20];
        int totalLength = header.length + payload.length;

        header[0] = 0x45;                              // IPv4, 5 words
        header[2] = (byte) (totalLength >> 8);
        header[3] = (byte) totalLength;
        header[8] = 64;                                // TTL
        header[9] = protocol;

        writeAddress(header, 12, src);
        writeAddress(header, 16, dst);

        byte[] packet = new byte[totalLength];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(payload, 0, packet, header.length, payload.length);
        return packet;
    }

    private static void writeAddress(byte[] target, int offset, String address) {
        try {
            byte[] bytes = InetAddress.getByName(address).getAddress();
            System.arraycopy(bytes, 0, target, offset, 4);
        } catch (UnknownHostException e) {
            throw new IllegalStateException("bad address " + address, e);
        }
    }

    private static byte[] ethernet(byte[] payload) {
        byte[] frame = new byte[14 + payload.length];
        System.arraycopy(DST_MAC, 0, frame, 0, 6);
        System.arraycopy(SRC_MAC, 0, frame, 6, 6);
        frame[12] = 0x08;                              // EtherType IPv4
        frame[13] = 0x00;
        System.arraycopy(payload, 0, frame, 14, payload.length);
        return frame;
    }

    /** A single capture record: timestamp (epoch millis) + packet. */
    public static final class Record {
        public final long timestampMillis;
        public final byte[] frame;

        public Record(long timestampMillis, byte[] frame) {
            this.timestampMillis = timestampMillis;
            this.frame = frame;
        }
    }

    /** Builds a representative capture: IKE exchange followed by an ESP data phase. */
    public static List<Record> ipsecSession(int espPackets, int protocol, long startMillis) {
        List<Record> records = new ArrayList<>();
        long t = startMillis;

        // IKE_SA_INIT + IKE_AUTH (both directions)
        records.add(new Record(t, udpPacket(CLIENT_IP, SERVER_IP, 500, 500, 260)));
        t += 2;
        records.add(new Record(t, udpPacket(SERVER_IP, CLIENT_IP, 500, 500, 300)));
        t += 3;
        records.add(new Record(t, udpPacket(CLIENT_IP, SERVER_IP, 4500, 4500, 380)));
        t += 4;
        records.add(new Record(t, udpPacket(SERVER_IP, CLIENT_IP, 4500, 4500, 420)));
        t += 10;

        int[] gaps = {2, 6, 20, 80, 300};
        for (int i = 0; i < espPackets; i++) {
            int size = (i % 5 == 0) ? 1200 : (i % 3 == 0 ? 500 : 90);
            records.add(new Record(t, ipsecPacket(CLIENT_IP, SERVER_IP, protocol, size)));
            t += gaps[i % gaps.length];
        }
        return records;
    }

    /** Writes records to a libpcap file (used by the parsing pipeline tests). */
    public static File writePcap(File target, List<Record> records) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(le32(0xA1B2C3D4));   // magic
        out.write(le16(2));            // major
        out.write(le16(4));            // minor
        out.write(le32(0));            // timezone
        out.write(le32(0));            // sigfigs
        out.write(le32(65535));        // snaplen
        out.write(le32(1));            // link type: Ethernet

        for (Record record : records) {
            out.write(le32((int) (record.timestampMillis / 1000)));
            out.write(le32((int) ((record.timestampMillis % 1000) * 1000)));
            out.write(le32(record.frame.length));
            out.write(le32(record.frame.length));
            out.write(record.frame);
        }

        try (FileOutputStream fileOut = new FileOutputStream(target)) {
            fileOut.write(out.toByteArray());
        }
        return target;
    }

    /** Convenience: parsed packets with their timestamps, as the extractor consumes them. */
    public static List<TimestampedPacket> toTimestampedPackets(List<Record> records) {
        List<TimestampedPacket> packets = new ArrayList<>(records.size());
        for (Record record : records) {
            packets.add(new TimestampedPacket(parseEthernet(record.frame), record.timestampMillis));
        }
        return packets;
    }

    private static byte[] le32(int value) {
        return new byte[]{
            (byte) value, (byte) (value >> 8), (byte) (value >> 16), (byte) (value >> 24)
        };
    }

    private static byte[] le16(int value) {
        return new byte[]{(byte) value, (byte) (value >> 8)};
    }

    public static Inet4Address address(String value) {
        try {
            return (Inet4Address) InetAddress.getByName(value);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }
}
