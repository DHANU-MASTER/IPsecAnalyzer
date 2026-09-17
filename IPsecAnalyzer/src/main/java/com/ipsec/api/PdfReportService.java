package com.ipsec.api;

import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.ipsec.features.FeatureExtractor;
import com.ipsec.ml.Predictor;
import com.ipsec.scoring.SecurityScorer;
import com.ipsec.scoring.ThreatMatrix;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * Real PDF report generation (OpenPDF). Produces a styled, multi-section
 * document from the same assessment data that the dashboard renders.
 *
 * The text reports (ReportService) remain the plain-text source of truth;
 * this renders the same content as a professional PDF for stakeholders.
 */
public final class PdfReportService {

    private static final DateTimeFormatter TS =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final Color HEADER_BG = new Color(15, 46, 84);
    private static final Color LIGHT_BG = new Color(240, 244, 248);
    private static final Color RED = new Color(192, 57, 43);
    private static final Color ORANGE = new Color(211, 84, 0);
    private static final Color GREEN = new Color(39, 130, 70);

    private PdfReportService() {
    }

    public static byte[] executiveReport(SecurityScorer.SecurityAssessment assessment,
                                         List<ThreatMatrix.Threat> threats) {
        try {
            Document doc = newDocument("IPsec Security - Executive Summary");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            PdfWriter.getInstance(doc, out);
            doc.open();

            title(doc, "Executive Summary");
            meta(doc, "IPsec Analyzer | Smart India Hackathon 2026 (NTRO PS 26160)");

            // ---- risk banner -------------------------------------------------
            PdfPTable risk = new PdfPTable(new float[]{1.2f, 1.2f, 1.6f});
            risk.setWidthPercentage(100);
            risk.setSpacingBefore(10);
            risk.addCell(cell("Overall Risk Score", headerFont(), HEADER_BG));
            risk.addCell(cell("Risk Level", headerFont(), HEADER_BG));
            risk.addCell(cell("Generated", headerFont(), HEADER_BG));
            risk.addCell(cell(String.format("%.1f / 100", assessment.overallRiskScore), bigFont(), LIGHT_BG));
            risk.addCell(cell(assessment.riskLevel, bigFont(), levelColor(assessment.riskLevel)));
            risk.addCell(cell(LocalDateTime.now().format(TS), bodyFont(), LIGHT_BG));
            doc.add(risk);

            // ---- key findings ------------------------------------------------
            section(doc, "Key Findings");
            if (assessment.vulnerabilities.isEmpty()) {
                doc.add(bullet("No significant vulnerabilities identified in this capture.", GREEN));
            } else {
                for (String v : assessment.vulnerabilities) {
                    doc.add(bullet(v, RED));
                }
            }

            // ---- recommendations ----------------------------------------------
            section(doc, "Recommendations");
            for (String r : assessment.recommendations) {
                doc.add(bullet(r, HEADER_BG));
            }

            // ---- threat matrix --------------------------------------------------
            section(doc, "Threat Matrix (" + threats.size() + " items)");
            PdfPTable table = new PdfPTable(new float[]{1.0f, 2.6f, 3.4f});
            table.setWidthPercentage(100);
            table.addCell(cell("Severity", headerFont(), HEADER_BG));
            table.addCell(cell("Threat", headerFont(), HEADER_BG));
            table.addCell(cell("Mitigation", headerFont(), HEADER_BG));
            for (ThreatMatrix.Threat t : threats) {
                Color sev = "Critical".equalsIgnoreCase(t.severity) ? RED
                    : "High".equalsIgnoreCase(t.severity) ? ORANGE : LIGHT_BG;
                table.addCell(cell(t.severity, bodyFont(), sev));
                table.addCell(cell(t.name, bodyFont(), null));
                table.addCell(cell(t.mitigation, smallFont(), null));
            }
            doc.add(table);

            footer(doc);
            doc.close();
            return out.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException("PDF generation failed: " + e.getMessage(), e);
        }
    }

    public static byte[] technicalReport(FeatureExtractor.PacketFeatures features,
                                         Predictor.PredictionResult prediction,
                                         SecurityScorer.SecurityAssessment assessment,
                                         List<ThreatMatrix.Threat> threats) {
        try {
            Document doc = newDocument("IPsec Security - Technical Analysis");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            PdfWriter.getInstance(doc, out);
            doc.open();

            title(doc, "Technical Analysis Report");
            meta(doc, "Generated " + LocalDateTime.now().format(TS)
                + " | ML basis: " + String.valueOf(prediction.modelBasis));

            // ---- traffic characteristics ---------------------------------------
            section(doc, "Captured Traffic Characteristics");
            PdfPTable traffic = new PdfPTable(new float[]{2.4f, 1.2f});
            traffic.setWidthPercentage(100);
            traffic.addCell(cell("Metric", headerFont(), HEADER_BG));
            traffic.addCell(cell("Value", headerFont(), HEADER_BG));
            traffic.addCell(cell("Average packet size", bodyFont(), null));
            traffic.addCell(cell(String.format("%.2f bytes", features.avgPacketSize), bodyFont(), LIGHT_BG));
            traffic.addCell(cell("Std deviation of packet size", bodyFont(), null));
            traffic.addCell(cell(String.format("%.2f bytes", features.stdPacketSize), bodyFont(), LIGHT_BG));
            traffic.addCell(cell("Average inter-arrival time", bodyFont(), null));
            traffic.addCell(cell(String.format("%.2f ms", features.avgInterArrivalTime), bodyFont(), LIGHT_BG));
            traffic.addCell(cell("Std deviation of inter-arrival time", bodyFont(), null));
            traffic.addCell(cell(String.format("%.2f ms", features.stdInterArrivalTime), bodyFont(), LIGHT_BG));
            traffic.addCell(cell("IKE negotiation packets", bodyFont(), null));
            traffic.addCell(cell(String.valueOf(features.ikeNegotiationCount), bodyFont(), LIGHT_BG));
            traffic.addCell(cell("ESP data packets", bodyFont(), null));
            traffic.addCell(cell(String.valueOf(features.espPacketCount), bodyFont(), LIGHT_BG));
            traffic.addCell(cell("AH packets", bodyFont(), null));
            traffic.addCell(cell(String.valueOf(features.ahPacketCount), bodyFont(), LIGHT_BG));
            traffic.addCell(cell("Detected IPsec protocol", bodyFont(), null));
            traffic.addCell(cell(protocolName(features.ipsecProtocol), bodyFont(), LIGHT_BG));
            traffic.addCell(cell("Session duration", bodyFont(), null));
            traffic.addCell(cell(features.sessionDuration + " s", bodyFont(), LIGHT_BG));
            doc.add(traffic);

            // ---- ML classification ------------------------------------------------
            section(doc, "AI Classification Results");
            PdfPTable ml = new PdfPTable(new float[]{2.0f, 1.2f, 1.2f});
            ml.setWidthPercentage(100);
            ml.addCell(cell("Attribute", headerFont(), HEADER_BG));
            ml.addCell(cell("Prediction", headerFont(), HEADER_BG));
            ml.addCell(cell("Confidence", headerFont(), HEADER_BG));
            ml.addCell(cell("Cipher suite", bodyFont(), null));
            ml.addCell(cell(prediction.predictedCipher, boldFont(), LIGHT_BG));
            ml.addCell(cell(String.format("%.1f%%", prediction.cipherConfidence * 100), bodyFont(), LIGHT_BG));
            ml.addCell(cell("Tunnel mode", bodyFont(), null));
            ml.addCell(cell(prediction.predictedTunnelMode, boldFont(), LIGHT_BG));
            ml.addCell(cell(String.format("%.1f%%", prediction.tunnelConfidence * 100), bodyFont(), LIGHT_BG));
            doc.add(ml);

            // ---- component scores ------------------------------------------------
            section(doc, "Security Assessment Component Scores");
            PdfPTable scores = new PdfPTable(new float[]{2.4f, 1.0f});
            scores.setWidthPercentage(100);
            scores.addCell(cell("Component", headerFont(), HEADER_BG));
            scores.addCell(cell("Score", headerFont(), HEADER_BG));
            for (Map.Entry<String, Double> e : assessment.componentScores.entrySet()) {
                scores.addCell(cell(e.getKey(), bodyFont(), null));
                scores.addCell(cell(String.format("%.1f", e.getValue()), bodyFont(), LIGHT_BG));
            }
            doc.add(scores);

            // ---- threat matrix ------------------------------------------------------
            section(doc, "Threat Matrix");
            PdfPTable table = new PdfPTable(new float[]{1.0f, 2.6f, 1.2f, 3.2f});
            table.setWidthPercentage(100);
            table.addCell(cell("Severity", headerFont(), HEADER_BG));
            table.addCell(cell("Threat", headerFont(), HEADER_BG));
            table.addCell(cell("Likelihood", headerFont(), HEADER_BG));
            table.addCell(cell("Mitigation", headerFont(), HEADER_BG));
            for (ThreatMatrix.Threat t : threats) {
                Color sev = "Critical".equalsIgnoreCase(t.severity) ? RED
                    : "High".equalsIgnoreCase(t.severity) ? ORANGE : LIGHT_BG;
                table.addCell(cell(t.severity, bodyFont(), sev));
                table.addCell(cell(t.name, bodyFont(), null));
                table.addCell(cell(t.likelihood, bodyFont(), null));
                table.addCell(cell(t.mitigation, smallFont(), null));
            }
            doc.add(table);

            footer(doc);
            doc.close();
            return out.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException("PDF generation failed: " + e.getMessage(), e);
        }
    }

    // ---- document scaffolding ------------------------------------------------

    private static Document newDocument(String title) {
        Document doc = new Document(PageSize.A4, 40, 40, 46, 40);
        doc.addTitle(title);
        doc.addCreator("IPsec Analyzer");
        return doc;
    }

    private static void title(Document doc, String text) throws Exception {
        Paragraph p = new Paragraph(text, new Font(Font.HELVETICA, 20, Font.BOLD, HEADER_BG));
        p.setSpacingAfter(2);
        doc.add(p);
    }

    private static void meta(Document doc, String text) throws Exception {
        Paragraph p = new Paragraph(text, new Font(Font.HELVETICA, 9, Font.NORMAL, Color.GRAY));
        p.setSpacingAfter(12);
        doc.add(p);
    }

    private static void section(Document doc, String text) throws Exception {
        Paragraph p = new Paragraph(text, new Font(Font.HELVETICA, 13, Font.BOLD, HEADER_BG));
        p.setSpacingBefore(14);
        p.setSpacingAfter(6);
        doc.add(p);
    }

    private static void footer(Document doc) throws Exception {
        Paragraph p = new Paragraph(
            "Generated by IPsec Analyzer | all values computed from the analyzed capture",
            new Font(Font.HELVETICA, 8, Font.ITALIC, Color.GRAY));
        p.setSpacingBefore(16);
        doc.add(p);
    }

    private static Paragraph bullet(String text, Color dot) {
        Paragraph p = new Paragraph("", bodyFont());
        p.add(new Phrase("\u2022 ", new Font(Font.HELVETICA, 10, Font.BOLD, dot)));
        p.add(new Phrase(text, bodyFont()));
        p.setSpacingAfter(4);
        p.setIndentationLeft(10);
        return p;
    }

    private static PdfPCell cell(String text, Font font, Color bg) {
        PdfPCell c = new PdfPCell(new Phrase(text, font));
        c.setPadding(5);
        c.setBackgroundColor(bg == null ? Color.WHITE : bg);
        c.setBorderColor(new Color(210, 214, 220));
        return c;
    }

    private static Color levelColor(String level) {
        if (level == null) {
            return LIGHT_BG;
        }
        return switch (level.toLowerCase()) {
            case "critical", "high" -> RED;
            case "medium" -> ORANGE;
            default -> GREEN;
        };
    }

    private static String protocolName(int proto) {
        return switch (proto) {
            case 50 -> "50 (ESP)";
            case 51 -> "51 (AH)";
            default -> "none detected";
        };
    }

    private static Font bodyFont() {
        return new Font(Font.HELVETICA, 9);
    }

    private static Font smallFont() {
        return new Font(Font.HELVETICA, 8);
    }

    private static Font boldFont() {
        return new Font(Font.HELVETICA, 9, Font.BOLD);
    }

    private static Font bigFont() {
        return new Font(Font.HELVETICA, 11, Font.BOLD);
    }

    private static Font headerFont() {
        return new Font(Font.HELVETICA, 9, Font.BOLD, Color.WHITE);
    }
}
