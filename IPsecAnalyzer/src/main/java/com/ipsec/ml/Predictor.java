package com.ipsec.ml;

import weka.classifiers.trees.RandomForest;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SerializationHelper;

import java.io.File;

/**
 * Loads the trained RandomForest models (produced by {@link ModelTrainer} or
 * a dataset/ retrain) and runs inference. When the model files are absent it
 * triggers training once; if that also fails it degrades to an explicit,
 * labelled heuristic fallback so the analyzer never hard-fails.
 */
public class Predictor {

    private RandomForest cipherModel;
    private RandomForest tunnelModel;
    private Instances cipherHeader;
    private Instances tunnelHeader;

    /** Honest provenance of the last prediction ("model" or "heuristic"). */
    private String lastPredictionBasis = "heuristic";

    public Predictor() {
        loadModelsFromDisk("models");
    }

    public Predictor(RandomForest cipher, Instances cipherHeader,
                     RandomForest tunnel, Instances tunnelHeader) {
        this.cipherModel = cipher;
        this.tunnelModel = tunnel;
        this.cipherHeader = cipherHeader;
        this.tunnelHeader = tunnelHeader;
        this.lastPredictionBasis = "model";
    }

    public void loadModelsFromDisk(String modelsDir) {
        try {
            File dir = new File(modelsDir);
            if (!dir.exists()) {
                dir.mkdirs();
            }

            File cipherFile = new File(dir, "cipher_classifier.model");
            File tunnelFile = new File(dir, "tunnel_classifier.model");
            File cipherHeaderFile = new File(dir, "cipher_header.arff");
            File tunnelHeaderFile = new File(dir, "tunnel_header.arff");

            if (!cipherFile.exists() || !tunnelFile.exists()
                    || !cipherHeaderFile.exists() || !tunnelHeaderFile.exists()) {
                System.out.println("[INFO] Training Weka models (real pipeline: synthetic captures "
                    + "-> feature extraction -> RandomForest) in " + modelsDir + "...");
                ModelTrainer.TrainingReport report = ModelTrainer.train(modelsDir);
                if (report.error != null) {
                    System.err.println("[WARN] Model training failed: " + report.error);
                }
            }

            if (cipherFile.exists() && tunnelFile.exists()
                    && cipherHeaderFile.exists() && tunnelHeaderFile.exists()) {
                this.cipherModel = (RandomForest) SerializationHelper.read(cipherFile.getAbsolutePath());
                this.tunnelModel = (RandomForest) SerializationHelper.read(tunnelFile.getAbsolutePath());
                this.cipherHeader = (Instances) SerializationHelper.read(cipherHeaderFile.getAbsolutePath());
                this.tunnelHeader = (Instances) SerializationHelper.read(tunnelHeaderFile.getAbsolutePath());
                this.lastPredictionBasis = "model";
                System.out.println("Predictor loaded Weka models from " + dir.getAbsolutePath());
            }
        } catch (Exception e) {
            System.err.println("[WARN] Predictor model loading fallback: " + e.getMessage());
        }
    }

    public boolean hasModels() {
        return cipherModel != null && tunnelModel != null
            && cipherHeader != null && tunnelHeader != null;
    }

    public String getLastPredictionBasis() {
        return lastPredictionBasis;
    }

    public PredictionResult predict(double avgPktSize, double stdPktSize,
                                    double avgIAT, double stdIAT,
                                    int ikeCount, int espCount) throws Exception {

        PredictionResult result = new PredictionResult();

        if (hasModels()) {
            double[] cipherOut = runModel(cipherModel, cipherHeader,
                avgPktSize, stdPktSize, avgIAT, stdIAT, ikeCount, espCount);
            double[] tunnelOut = runModel(tunnelModel, tunnelHeader,
                avgPktSize, stdPktSize, avgIAT, stdIAT, ikeCount, espCount);

            result.predictedCipher = cipherHeader.classAttribute().value((int) cipherOut[0]);
            result.predictedTunnelMode = tunnelHeader.classAttribute().value((int) tunnelOut[0]);
            // REAL distribution confidences from the forests (no artificial floor)
            result.cipherConfidence = round4(cipherOut[1]);
            result.tunnelConfidence = round4(tunnelOut[1]);
            result.modelBasis = "trained RandomForest (Weka) — "
                + cipherHeader.numInstances() + " training instances";
            lastPredictionBasis = "model";
        } else {
            // Explicit heuristic fallback, labelled as such everywhere it is shown
            if (avgPktSize > 1000) {
                result.predictedCipher = "AES-256-GCM";
                result.predictedTunnelMode = "Tunnel";
                result.cipherConfidence = 0.75;
                result.tunnelConfidence = 0.80;
            } else if (avgPktSize > 400 || (espCount > 0 && ikeCount > 0)) {
                result.predictedCipher = "AES-128";
                result.predictedTunnelMode = "Tunnel";
                result.cipherConfidence = 0.65;
                result.tunnelConfidence = 0.72;
            } else if (avgPktSize > 0) {
                result.predictedCipher = "3DES-CBC";
                result.predictedTunnelMode = "Transport";
                result.cipherConfidence = 0.55;
                result.tunnelConfidence = 0.60;
            } else {
                result.predictedCipher = "AES-256-GCM";
                result.predictedTunnelMode = "Tunnel";
                result.cipherConfidence = 0.50;
                result.tunnelConfidence = 0.50;
            }
            result.modelBasis = "heuristic fallback (no trained model files)";
            lastPredictionBasis = "heuristic";
        }

        return result;
    }

    private double[] runModel(RandomForest model, Instances header,
                              double avgPktSize, double stdPktSize,
                              double avgIAT, double stdIAT,
                              int ikeCount, int espCount) throws Exception {
        double[] values = new double[header.numAttributes()];
        double[] features = {avgPktSize, stdPktSize, avgIAT, stdIAT, ikeCount, espCount};
        for (int i = 0; i < Math.min(values.length, features.length); i++) {
            values[i] = features[i];
        }

        Instance inst = new DenseInstance(1.0, values);
        inst.setDataset(header);

        double cls = model.classifyInstance(inst);
        double[] dist = model.distributionForInstance(inst);
        double confidence = (cls >= 0 && cls < dist.length) ? dist[(int) cls] : 0.5;
        return new double[]{cls, confidence};
    }

    private static double round4(double v) {
        return Math.round(v * 10000.0) / 10000.0;
    }

    public static class PredictionResult {
        public String predictedCipher;
        public String predictedTunnelMode;
        public double cipherConfidence;
        public double tunnelConfidence;
        /** Where the prediction came from — always surfaced to the caller. */
        public String modelBasis;
    }
}
