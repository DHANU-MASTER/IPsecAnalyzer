package com.ipsec.ml;

import com.ipsec.capture.PcapReader;
import com.ipsec.features.FeatureExtractor;
import weka.classifiers.trees.RandomForest;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.OptionHandler;
import weka.core.SerializationHelper;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * REAL model training pipeline that runs inside the app.
 *
 * 1. Generates labeled synthetic IPsec captures (pcap files) for each traffic
 *    profile — bulk-data, interactive, legacy, and near-idle.
 * 2. Extracts features from those pcaps with the PRODUCTION pipeline
 *    (PcapReader + FeatureExtractor, real packet timestamps) — identical to
 *    what a user upload goes through.
 * 3. Trains two Weka RandomForests: cipher-suite class and tunnel mode.
 * 4. Evaluates on the training set (honest: this is a fit check, not a
 *    held-out score) and serializes the models + headers to models/.
 *
 * After this runs, Predictor uses the trained models instead of heuristics,
 * and /health reports ml_model: LOADED. The bootstrap labels come from the
 * generating profiles (synthetic data); swapping in labeled real captures
 * from dataset/ is the path to production accuracy.
 */
public class ModelTrainer {

    public static class TrainingReport {
        public boolean trained;
        public String reason;
        public int capturesGenerated;
        public int instancesTrained;
        public int cipherClasses;
        public int modeClasses;
        public double cipherTrainingAccuracy;
        public double modeTrainingAccuracy;
        public long durationMs;
        public String modelsDir;
        public String dataBasis;
        public String error;
        /** Captures ingested from dataset/ (real labeled data). */
        public int realCapturesUsed;
    }

    /** One labeled traffic profile -> distinct feature signature. */
    private record Profile(
            String label, String mode, int espCount, int espPayload,
            int ikeCount, int fillers, long iatMicros, long jitterMicros,
            int seeds) {
    }

    private static final List<Profile> PROFILES = List.of(
        new Profile("AES-256-GCM", "Tunnel", 120, 1300, 1, 8, 5_000L, 2_000L, 20),
        new Profile("ChaCha20-Poly1305", "Tunnel", 110, 1250, 1, 8, 5_500L, 2_500L, 20),
        new Profile("AES-128", "Tunnel", 60, 600, 3, 6, 20_000L, 8_000L, 20),
        new Profile("3DES-CBC", "Transport", 40, 1300, 8, 2, 50_000L, 25_000L, 20),
        new Profile("AES-128", "Transport", 25, 150, 6, 3, 80_000L, 40_000L, 20)
    );

    /** Trains only when the model files are absent (startup path). */
    public static TrainingReport trainIfNeeded(String modelsDir) {
        if (modelsExist(modelsDir)) {
            TrainingReport r = new TrainingReport();
            r.trained = false;
            r.reason = "models already present";
            r.modelsDir = modelsDir;
            return r;
        }
        return train(modelsDir);
    }

    /** Forces a fresh training run (used by the /api/ml/retrain endpoint). */
    public static TrainingReport retrain(String modelsDir) {
        return train(modelsDir);
    }

    public static TrainingReport train(String modelsDir) {
        TrainingReport report = new TrainingReport();
        report.modelsDir = modelsDir;
        long start = System.currentTimeMillis();
        File dir = new File(modelsDir);
        if (!dir.exists() && !dir.mkdirs()) {
            report.error = "cannot create models dir: " + modelsDir;
            return report;
        }
        File tmpCaptures = new File(System.getProperty("java.io.tmpdir"), "ipsec_training_captures");
        try {
            Files.createDirectories(tmpCaptures.toPath());

            // ---- 1 + 2: generate captures, extract features with the real pipeline
            List<double[]> featureRows = new ArrayList<>();
            List<String> cipherLabels = new ArrayList<>();
            List<String> modeLabels = new ArrayList<>();
            int captures = 0;
            int realCaptures = ingestRealCaptures(datasetDir(), featureRows, cipherLabels, modeLabels);
            captures += realCaptures;

            for (Profile p : PROFILES) {
                for (int seed = 0; seed < p.seeds(); seed++) {
                    byte[] pcap = buildPcap(p, seed);
                    File f = new File(tmpCaptures, p.label().replace('/', '_') + "_" + seed + ".pcap");
                    try (OutputStream out = new FileOutputStream(f)) {
                        out.write(pcap);
                    }
                    List<PcapReader.TimestampedPacket> packets =
                        PcapReader.readPcapWithTimestamps(f.getAbsolutePath());
                    FeatureExtractor.PacketFeatures fx = FeatureExtractor.extract(packets);

                    // attribute order must match Predictor.runModel
                    featureRows.add(new double[]{
                        fx.avgPacketSize, fx.stdPacketSize,
                        fx.avgInterArrivalTime, fx.stdInterArrivalTime,
                        fx.ikeNegotiationCount, fx.espPacketCount});
                    cipherLabels.add(p.label());
                    modeLabels.add(p.mode());
                    captures++;
                    Files.deleteIfExists(f.toPath());
                }
            }

            // ---- 3: build Instances + train both forests
            List<String> cipherClasses = new ArrayList<>(
                PROFILES.stream().map(Profile::label).distinct().sorted().toList());
            List<String> modeClasses = new ArrayList<>(
                PROFILES.stream().map(Profile::mode).distinct().sorted().toList());
            // labels from real captures may introduce classes beyond the synthetic profiles
            for (String l : cipherLabels) {
                if (!cipherClasses.contains(l)) {
                    cipherClasses.add(l);
                }
            }
            for (String l : modeLabels) {
                if (!modeClasses.contains(l)) {
                    modeClasses.add(l);
                }
            }

            Instances cipherData = buildDataset("IPsecCipher", cipherClasses, featureRows, cipherLabels);
            Instances modeData = buildDataset("IPsecTunnelMode", modeClasses, featureRows, modeLabels);

            RandomForest cipherModel = buildForest();
            cipherModel.buildClassifier(cipherData);
            RandomForest modeModel = buildForest();
            modeModel.buildClassifier(modeData);

            // ---- 4: honest fit check on the training set
            report.cipherTrainingAccuracy = trainingAccuracy(cipherModel, cipherData);
            report.modeTrainingAccuracy = trainingAccuracy(modeModel, modeData);

            SerializationHelper.write(new File(dir, "cipher_classifier.model").getAbsolutePath(), cipherModel);
            SerializationHelper.write(new File(dir, "tunnel_classifier.model").getAbsolutePath(), modeModel);
            SerializationHelper.write(new File(dir, "cipher_header.arff").getAbsolutePath(), cipherData);
            SerializationHelper.write(new File(dir, "tunnel_header.arff").getAbsolutePath(), modeData);

            report.trained = true;
            report.reason = realCaptures > 0
                ? "trained on " + realCaptures + " REAL dataset captures + "
                    + (featureRows.size() - realCaptures) + " synthetic bootstrap captures = "
                    + featureRows.size() + " instances, " + cipherClasses.size() + " cipher classes"
                : "trained " + captures + " synthetic captures -> "
                    + featureRows.size() + " instances, " + cipherClasses.size() + " cipher classes";
            report.capturesGenerated = captures;
            report.instancesTrained = featureRows.size();
            report.cipherClasses = cipherClasses.size();
            report.modeClasses = modeClasses.size();
            report.realCapturesUsed = realCaptures;
            report.dataBasis = realCaptures > 0
                ? "features extracted by the production pipeline from " + realCaptures
                    + " labeled REAL captures in dataset/ + "
                    + (featureRows.size() - realCaptures) + " synthetic bootstrap captures"
                : "features extracted by the production pipeline from generated labeled "
                    + "pcaps (real packet timestamps); bootstrap training set — add labeled "
                    + "real captures to dataset/ for production accuracy";
        } catch (Exception e) {
            report.error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            try {
                if (tmpCaptures.exists()) {
                    Files.list(tmpCaptures.toPath()).forEach(p -> p.toFile().delete());
                    tmpCaptures.delete();
                }
            } catch (Exception ignored) {
            }
        }
        report.durationMs = System.currentTimeMillis() - start;
        return report;
    }

    public static boolean modelsExist(String modelsDir) {
        File dir = new File(modelsDir);
        return new File(dir, "cipher_classifier.model").exists()
            && new File(dir, "tunnel_classifier.model").exists()
            && new File(dir, "cipher_header.arff").exists()
            && new File(dir, "tunnel_header.arff").exists();
    }

    // ---- real dataset ingestion ---------------------------------------------

    /** Directory holding user-supplied labeled captures (mounted in compose). */
    static File datasetDir() {
        String env = System.getenv("DATASET_DIR");
        return new File(env != null && !env.isBlank() ? env : "dataset");
    }

    /**
     * Ingests labeled REAL captures from dataset/ into the training set.
     *
     * Naming convention: {@code cipher__mode__anything.pcap}, e.g.
     * {@code AES-256-GCM__Tunnel__site-a-2026-05-01.pcap} or
     * {@code ChaCha20-Poly1305__Transport__router1.pcap} (double underscore
     * separates the fields; case-insensitive). Features are extracted with the
     * production pipeline, so a capture with zero parseable packets is skipped.
     *
     * @return the number of captures successfully ingested
     */
    static int ingestRealCaptures(File datasetDir,
                                  List<double[]> featureRows,
                                  List<String> cipherLabels,
                                  List<String> modeLabels) {
        if (datasetDir == null || !datasetDir.isDirectory()) {
            return 0;
        }
        File[] files = datasetDir.listFiles((d, name) ->
            name.toLowerCase().endsWith(".pcap") && name.contains("__"));
        if (files == null) {
            return 0;
        }
        int ingested = 0;
        for (File f : files) {
            String[] parts = f.getName().substring(0, f.getName().length() - 5).split("__");
            if (parts.length < 2 || parts[0].isBlank() || parts[1].isBlank()) {
                System.err.println("[ModelTrainer] skipping malformed dataset name: " + f.getName());
                continue;
            }
            try {
                List<PcapReader.TimestampedPacket> packets =
                    PcapReader.readPcapWithTimestamps(f.getAbsolutePath());
                FeatureExtractor.PacketFeatures fx = FeatureExtractor.extract(packets);
                if (fx.espPacketCount == 0 && fx.ikeNegotiationCount == 0 && fx.ahPacketCount == 0) {
                    System.err.println("[ModelTrainer] skipping " + f.getName()
                        + " — no IPsec traffic detected");
                    continue;
                }
                featureRows.add(new double[]{
                    fx.avgPacketSize, fx.stdPacketSize,
                    fx.avgInterArrivalTime, fx.stdInterArrivalTime,
                    fx.ikeNegotiationCount, fx.espPacketCount});
                cipherLabels.add(parts[0].trim());
                modeLabels.add(parts[1].trim());
                ingested++;
            } catch (Exception e) {
                System.err.println("[ModelTrainer] skipping unreadable capture "
                    + f.getName() + ": " + e.getMessage());
            }
        }
        if (ingested > 0) {
            System.out.println("[ModelTrainer] ingested " + ingested
                + " real labeled capture(s) from " + datasetDir.getPath());
        }
        return ingested;
    }

    // ---- dataset assembly ----------------------------------------------------

    private static Instances buildDataset(String name, List<String> classes,
                                          List<double[]> rows, List<String> labels) {
        ArrayList<Attribute> attrs = new ArrayList<>();
        attrs.add(new Attribute("avgPacketSize"));
        attrs.add(new Attribute("stdPacketSize"));
        attrs.add(new Attribute("avgInterArrivalTime"));
        attrs.add(new Attribute("stdInterArrivalTime"));
        attrs.add(new Attribute("ikeNegotiationCount"));
        attrs.add(new Attribute("espPacketCount"));
        attrs.add(new Attribute("class", new ArrayList<>(classes)));

        Instances data = new Instances(name, attrs, rows.size());
        data.setClassIndex(attrs.size() - 1);
        for (int i = 0; i < rows.size(); i++) {
            double[] vals = new double[attrs.size()];
            System.arraycopy(rows.get(i), 0, vals, 0, 6);
            vals[6] = classes.indexOf(labels.get(i));
            Instance inst = new DenseInstance(1.0, vals);
            inst.setDataset(data);
            data.add(inst);
        }
        return data;
    }

    private static RandomForest buildForest() throws Exception {
        RandomForest rf = new RandomForest();
        ((OptionHandler) rf).setOptions(new String[]{"-I", "30"});
        return rf;
    }

    private static double trainingAccuracy(RandomForest model, Instances data) throws Exception {
        int correct = 0;
        for (int i = 0; i < data.numInstances(); i++) {
            double predicted = model.classifyInstance(data.instance(i));
            if (predicted == data.instance(i).classValue()) {
                correct++;
            }
        }
        return data.numInstances() == 0 ? 0 : Math.round(1000.0 * correct / data.numInstances()) / 10.0;
    }

    // ---- synthetic pcap generation (libpcap format, Ethernet link type) -------

    /**
     * Builds a complete .pcap file: one IKE SA establishment + data phase
     * matching the profile (ESP payload size, IAT distribution, filler noise).
     * Timestamps start at a fixed epoch + seed so every capture differs.
     */
    static byte[] buildPcap(Profile p, int seed) {
        Random rand = new Random(9000L + seed);
        long baseSec = 1_700_000_000L + seed * 60L;
        long baseUsec = rand.nextInt(1_000_000);

        List<byte[]> frames = new ArrayList<>();
        List<Long> offsetsUsec = new ArrayList<>();
        long t = 0; // microseconds since base

        // IKE_SA_INIT + IKE_AUTH exchanges (ports 500 then 4500)
        for (int i = 0; i < p.ikeCount(); i++) {
            int secondPort = (i % 2 == 0) ? 500 : 4500;
            frames.add(frame(udp(500, secondPort, ikePayload(rand)), false));
            offsetsUsec.add(t);
            t += p.iatMicros() + jitter(rand, p);
            frames.add(frame(udp(secondPort, 500, ikePayload(rand)), false));
            offsetsUsec.add(t);
            t += p.iatMicros() + jitter(rand, p);
        }
        // data phase: ESP carrier with profile-sized payloads
        for (int i = 0; i < p.espCount(); i++) {
            int payload = Math.max(1, p.espPayload() + rand.nextInt(41) - 20);
            frames.add(frame(esp(payload), true));
            offsetsUsec.add(t);
            t += p.iatMicros() + jitter(rand, p);
        }
        // non-IPsec filler noise so the model also sees ordinary traffic
        for (int i = 0; i < p.fillers(); i++) {
            frames.add(frame(udp(5353 + rand.nextInt(1000), 12345, new byte[24 + rand.nextInt(40)]), false));
            offsetsUsec.add(t);
            t += p.iatMicros() + jitter(rand, p);
        }

        return assemblePcap(baseSec, baseUsec, frames, offsetsUsec);
    }

    private static long jitter(Random rand, Profile p) {
        return (long) (rand.nextDouble() * 2 - 1) * p.jitterMicros();
    }

    /** Ethernet + IPv4 frame for the given L4 payload bytes (explicit IPsec flag). */
    private static byte[] frame(byte[] l4orEsp, boolean isEsp) {
        byte proto = isEsp ? (byte) 50 : (byte) 17;
        int ipTotal = 20 + l4orEsp.length;

        byte[] ip = new byte[ipTotal];
        ip[0] = 0x45;               // v4, IHL 5
        ip[1] = 0x00;               // DSCP
        ip[2] = (byte) (ipTotal >> 8);
        ip[3] = (byte) ipTotal;
        ip[4] = 0x00; ip[5] = 0x01; // id
        ip[6] = 0x40; ip[7] = 0x00; // don't fragment
        ip[8] = 64;                 // ttl
        ip[9] = proto;
        ip[10] = 0x00; ip[11] = 0x00; // checksum (not validated by the analyzer)
        ip[12] = 10; ip[13] = 0; ip[14] = 0; ip[15] = 1;   // 10.0.0.1
        ip[16] = 10; ip[17] = 0; ip[18] = 0; ip[19] = 2;   // 10.0.0.2
        System.arraycopy(l4orEsp, 0, ip, 20, l4orEsp.length);

        byte[] frame = new byte[14 + ip.length];
        byte[] dst = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e};
        byte[] src = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5f};
        System.arraycopy(dst, 0, frame, 0, 6);
        System.arraycopy(src, 0, frame, 6, 6);
        frame[12] = 0x08; frame[13] = 0x00;   // ethertype IPv4
        System.arraycopy(ip, 0, frame, 14, ip.length);
        return frame;
    }

    /** UDP datagram header (8B) + payload; the UDP header sits inside the IPv4 payload area. */
    private static byte[] udp(int srcPort, int dstPort, byte[] payload) {
        byte[] d = new byte[8 + payload.length];
        d[0] = (byte) (srcPort >> 8);
        d[1] = (byte) srcPort;
        d[2] = (byte) (dstPort >> 8);
        d[3] = (byte) dstPort;
        int len = d.length;
        d[4] = (byte) (len >> 8);
        d[5] = (byte) len;
        System.arraycopy(payload, 0, d, 8, payload.length);
        return d;
    }

    private static byte[] esp(int payloadSize) {
        byte[] d = new byte[Math.max(20, payloadSize)];
        new Random(1).nextBytes(d);                                 // random-ish ciphertext
        d[0] = (byte) 0x5A; d[1] = 0x11; d[2] = 0x22; d[3] = 0x33; // SPI
        return d;
    }

    private static byte[] ikePayload(Random rand) {
        byte[] d = new byte[64 + rand.nextInt(64)];
        d[0] = 0x21;                    // IKEv2 IKE_AUTH-ish first byte
        d[16] = 0x20; d[17] = 0x22;     // flags/version area
        rand.nextBytes(d);
        d[0] = 0x21;
        return d;
    }

    private static byte[] assemblePcap(long baseSec, long baseUsec, List<byte[]> frames, List<Long> offsetsUsec) {
        ByteArrayOutputStream pcap = new ByteArrayOutputStream();
        try {
            pcap.write(new byte[]{(byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1}); // magic (LE)
            pcap.write(le32(2));        // v2.4
            pcap.write(le32(0));        // tz
            pcap.write(le32(0));        // sigfigs
            pcap.write(le32(0x00010000)); // snaplen 64k
            pcap.write(le32(1));        // linktype Ethernet

            for (int i = 0; i < frames.size(); i++) {
                long absUsec = baseSec * 1_000_000L + baseUsec + offsetsUsec.get(i);
                long tsSec = absUsec / 1_000_000L;
                long tsUsec = absUsec % 1_000_000L;
                pcap.write(le32((int) tsSec));
                pcap.write(le32((int) tsUsec));
                pcap.write(le32(frames.get(i).length));
                pcap.write(le32(frames.get(i).length));
                pcap.write(frames.get(i));
            }
            return pcap.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] le32(int v) {
        return new byte[]{(byte) v, (byte) (v >> 8), (byte) (v >> 16), (byte) (v >> 24)};
    }
}
