package com.ipsec;

import com.ipsec.ml.ModelTrainer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
@EnableScheduling
public class IPsecAnalyzerApp {

    public static void main(String[] args) {
        // Weka's scheme resolver cannot see classes nested inside the Spring
        // Boot fat jar (Run.findSchemeMatch scans flat classpath entries only).
        // This Weka property switches ResourceUtils.forName to direct loading,
        // which works under the LaunchedURLClassLoader.
        System.setProperty("weka.test.maventest", "true");
        trainModelsIfNeeded();
        SpringApplication.run(IPsecAnalyzerApp.class, args);
    }

    /**
     * Trains the RandomForest models on first boot through the real pipeline
     * (synthetic labeled captures -> production feature extraction -> Weka),
     * so every later prediction is model-backed and /health reports READY.
     * Deleting models/ or calling POST /api/ml/retrain re-runs training.
     */
    private static void trainModelsIfNeeded() {
        try {
            if (!ModelTrainer.modelsExist("models")) {
                System.out.println("[INFO] Training Weka classifiers (pcap pipeline -> RandomForest)...");
                ModelTrainer.TrainingReport r = ModelTrainer.train("models");
                if (r.error != null) {
                    System.err.println("[WARN] Model training failed: " + r.error);
                } else {
                    System.out.println("[INFO] " + r.reason
                        + " | cipher fit " + r.cipherTrainingAccuracy + "%"
                        + ", mode fit " + r.modeTrainingAccuracy + "%"
                        + " in " + r.durationMs + " ms");
                }
            } else {
                System.out.println("[INFO] Trained Weka models found in models/ — loading.");
            }
        } catch (Exception e) {
            System.err.println("[WARN] Could not train Weka models: " + e.getMessage());
        }
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
