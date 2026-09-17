package com.ipsec;

import com.ipsec.ml.ModelTrainer;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pcap4j.core.Pcaps;
import weka.classifiers.trees.RandomForest;
import weka.core.Instances;
import weka.core.SerializationHelper;

import java.io.File;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end training smoke test: generates labeled synthetic captures,
 * extracts features through the production pipeline (requires libpcap),
 * trains RandomForest models, and confirms they serialize and reload.
 */
class ModelTrainerTest {

    private static File tempModels;

    @BeforeAll
    static void requireLibpcap() {
        boolean available;
        try {
            Pcaps.libVersion();
            available = true;
        } catch (Throwable notAvailable) {
            available = false;
        }
        Assumptions.assumeTrue(available, "native libpcap not available - skipping training test");
    }

    @Test
    @DisplayName("Trainer produces real models that reload and predict")
    void trainsAndReloadsModels() throws Exception {
        tempModels = Files.createTempDirectory("ipsec-models-test").toFile();

        ModelTrainer.TrainingReport report = ModelTrainer.train(tempModels.getAbsolutePath());

        assertNotNull(report, "training must produce a report");
        assertTrue(report.error == null, "training must not fail: " + report.error);
        assertTrue(report.trained, "training must complete");
        assertTrue(report.capturesGenerated >= 100, "multiple captures must be generated");
        assertTrue(report.instancesTrained == report.capturesGenerated,
            "one instance per capture");
        assertTrue(report.cipherClasses >= 3, "cipher classes must be covered");
        assertTrue(report.cipherTrainingAccuracy > 60.0,
            "forests must fit the synthetic profiles reasonably: " + report.cipherTrainingAccuracy);

        // all four artifacts must exist
        for (String f : new String[]{
                "cipher_classifier.model", "tunnel_classifier.model",
                "cipher_header.arff", "tunnel_header.arff"}) {
            assertTrue(new File(tempModels, f).isFile(), f + " must be written");
        }

        // models must reload and be usable for inference
        RandomForest cipher = (RandomForest)
            SerializationHelper.read(new File(tempModels, "cipher_classifier.model").getAbsolutePath());
        Instances header = (Instances)
            SerializationHelper.read(new File(tempModels, "cipher_header.arff").getAbsolutePath());
        weka.core.DenseInstance inst = new weka.core.DenseInstance(1.0,
            new double[]{1300, 150, 5.0, 2.0, 1, 120});
        inst.setDataset(header);
        double cls = cipher.classifyInstance(inst);
        String predicted = header.classAttribute().value((int) cls);
        assertNotNull(predicted, "reloaded model must classify");
        assertTrue(cls >= 0 && cls < header.classAttribute().numValues(),
            "predicted index must be within the class attribute");

        // idempotence: modelsExist must now report true
        assertTrue(ModelTrainer.modelsExist(tempModels.getAbsolutePath()));
        ModelTrainer.TrainingReport skip = ModelTrainer.trainIfNeeded(tempModels.getAbsolutePath());
        assertTrue(!skip.trained && skip.reason != null,
            "trainIfNeeded must skip when models already exist");
    }
}
