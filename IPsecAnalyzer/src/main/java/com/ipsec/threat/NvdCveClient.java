package com.ipsec.threat;

import com.ipsec.crypto.CryptoKit;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * REAL Layer-0 threat-intelligence feed: queries the live NVD 2.0 API
 * (https://services.nvd.nist.gov/rest/json/cves/2.0) for CVEs matching the
 * detected cipher / protocol keywords.
 *
 *  - Results are cached in-process for {@link #CACHE_TTL}; the cache key is
 *    the query, so repeated analyses with the same cipher do not re-hit NVD.
 *  - Every response carries {@code feedBasis} stating where the CVEs came
 *    from ("live NVD" vs "local fallback catalog") and the fetch timestamp.
 *  - If the network is unavailable, the API errors, or the response cannot be
 *    parsed, the caller gets a SMALL static fallback list explicitly labeled
 *    as such — never presented as live data.
 *
 * No API key is used (NVD rate-limits keyless clients to ~5 req/30s, which
 * the cache easily absorbs). Set NVD_API_KEY to raise the rate limit.
 */
public class NvdCveClient {

    private static final String NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final Duration CACHE_TTL = Duration.ofMinutes(60);
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(5);

    /** Cipher/keyword -> NVD search terms, mapped from the observed capture. */
    private static final java.util.Map<String, String[]> CIPHER_KEYWORDS = java.util.Map.of(
        "3DES", new String[]{"3DES", "Sweet32"},
        "DES", new String[]{"3DES", "Sweet32"},
        "AES-CBC", new String[]{"IPsec CBC padding oracle"},
        "CBC", new String[]{"IPsec CBC padding oracle"},
        "AES-128", new String[]{"AES-128 IPsec"},
        "AES-256", new String[]{"AES-256 IPsec"},
        "IKE", new String[]{"Internet Key Exchange IKEv2"}
    );

    /** Simple TTL cache keyed by query string. */
    private static final class CacheEntry {
        final List<ThreatIntelligenceEngine.ThreatIntel> items;
        final LocalDateTime fetchedAt;
        CacheEntry(List<ThreatIntelligenceEngine.ThreatIntel> items, LocalDateTime fetchedAt) {
            this.items = items;
            this.fetchedAt = fetchedAt;
        }
    }

    private static final java.util.Map<String, CacheEntry> CACHE =
        new java.util.concurrent.ConcurrentHashMap<>();

    public static class FeedResult {
        public List<ThreatIntelligenceEngine.ThreatIntel> items;
        /** "live NVD 2.0 API" or "local fallback catalog (NVD unreachable)". */
        public String feedBasis;
        public String fetchedAt;
        public int resultsCount;
        public String query;
    }

    /**
     * Fetches CVE intel for the detected cipher from NVD, falling back to the
     * local catalog (labeled) on any failure.
     */
    public static FeedResult fetchForCipher(String detectedCipher) {
        String[] keywords = keywordsFor(detectedCipher);
        String query = String.join(" ", keywords);
        CacheEntry cached = CACHE.get(query);
        if (cached != null && Duration.between(cached.fetchedAt, LocalDateTime.now()).compareTo(CACHE_TTL) < 0) {
            return result(cached.items, "live NVD 2.0 API (cached)", cached.fetchedAt, query);
        }

        List<ThreatIntelligenceEngine.ThreatIntel> live = queryNvd(keywords);
        if (live != null && !live.isEmpty()) {
            CACHE.put(query, new CacheEntry(live, LocalDateTime.now()));
            return result(live, "live NVD 2.0 API", LocalDateTime.now(), query);
        }

        // Network/parse failure or genuinely no results: fall back, but say so.
        List<ThreatIntelligenceEngine.ThreatIntel> fallback =
            ThreatIntelligenceEngine.fallbackCatalogFor(detectedCipher);
        String basis = live != null
            ? "local fallback catalog (NVD returned no records for this query)"
            : "local fallback catalog (NVD unreachable)";
        return result(fallback, basis, LocalDateTime.now(), query);
    }

    private static String[] keywordsFor(String cipher) {
        if (cipher == null || cipher.isBlank()) {
            return new String[]{"IPsec"};
        }
        for (java.util.Map.Entry<String, String[]> e : CIPHER_KEYWORDS.entrySet()) {
            if (cipher.contains(e.getKey())) {
                return e.getValue();
            }
        }
        return new String[]{"IPsec"};
    }

    /** Queries the live NVD 2.0 API; null on any failure. */
    private static List<ThreatIntelligenceEngine.ThreatIntel> queryNvd(String[] keywords) {
        try {
            String kwParam = URLEncoder.encode(String.join(" ", keywords), StandardCharsets.UTF_8);
            String apiKey = System.getenv("NVD_API_KEY");
            HttpRequest.Builder req = HttpRequest.newBuilder()
                .uri(URI.create(NVD_URL + "?keywordSearch=" + kwParam + "&resultsPerPage=10"))
                .timeout(HTTP_TIMEOUT)
                .header("Accept", "application/json")
                .GET();
            if (apiKey != null && !apiKey.isBlank()) {
                req.header("apiKey", apiKey);
            }

            HttpClient client = HttpClient.newBuilder().connectTimeout(HTTP_TIMEOUT).build();
            HttpResponse<String> resp = client.send(req.build(), HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                System.err.println("[NVD] HTTP " + resp.statusCode() + " — falling back to local catalog");
                return null;
            }
            return parseNvdJson(resp.body());
        } catch (Exception ex) {
            System.err.println("[NVD] query failed (" + ex.getClass().getSimpleName()
                + ": " + ex.getMessage() + ") — falling back to local catalog");
            return null;
        }
    }

    /**
     * Minimal parser for the NVD 2.0 JSON shape:
     * { "vulnerabilities": [ { "cve": { "id": ..., "descriptions": [...],
     *   "metrics": { "cvssMetricV31": [ { "cvssData": { "baseScore": ... } } ] },
     *   "published": "2024-...", "references": [...] } } ] }
     * Hand-rolled to avoid adding a JSON dependency to the runtime image.
     */
    public static List<ThreatIntelligenceEngine.ThreatIntel> parseNvdJson(String json) {
        List<ThreatIntelligenceEngine.ThreatIntel> out = new ArrayList<>();
        int vulnsIdx = json.indexOf("\"vulnerabilities\"");
        if (vulnsIdx < 0) {
            return out;
        }
        int cursor = json.indexOf('[', vulnsIdx);
        if (cursor < 0) {
            return out;
        }
        int depth = 0;
        int objStart = -1;
        for (int i = cursor; i < json.length() && out.size() < 10; i++) {
            char c = json.charAt(i);
            if (c == '[') {
                depth++;
            } else if (c == ']') {
                if (depth == 1 && objStart >= 0) {
                    // end of the vulnerabilities array
                    break;
                }
                depth--;
            } else if (c == '{') {
                if (depth == 1) {
                    objStart = i;
                }
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 1 && objStart >= 0) {
                    String cveObj = json.substring(objStart, i + 1);
                    ThreatIntelligenceEngine.ThreatIntel t = parseInto(cveObj);
                    if (t != null) {
                        out.add(t);
                    }
                    objStart = -1;
                }
            }
        }
        return out;
    }

    /** Extracts one CVE record from a "cve": { ... } JSON object fragment. */
    private static ThreatIntelligenceEngine.ThreatIntel parseInto(String cveJson) {
        try {
            String cveBlock = extractObject(cveJson, "\"cve\"");
            if (cveBlock == null) {
                return null;
            }
            String id = extractString(cveBlock, "\"id\"");
            if (id == null || !id.startsWith("CVE-")) {
                return null;
            }
            ThreatIntelligenceEngine.ThreatIntel t = new ThreatIntelligenceEngine.ThreatIntel();
            t.cveId = id;
            t.affected_cipher = extractString(cveBlock, "\"criteria\"") != null
                ? extractString(cveBlock, "\"criteria\"") : "see NVD record";
            t.description = extractEnglishDescription(cveBlock);
            t.severity = extractCvssSeverity(cveBlock);
            t.impact_score = extractCvssScore(cveBlock);
            t.disclosure_date = extractPublished(cveBlock);
            t.exploit_status = extractCisaExploitStatus(cveBlock);
            t.mitigation = "See NVD references for " + id + " (" + extractFirstReference(cveBlock) + ")";
            return t;
        } catch (Exception e) {
            return null;
        }
    }

    // ---- tiny JSON string/object extraction helpers -------------------------

    private static String extractString(String json, String key) {
        int k = json.indexOf(key);
        if (k < 0) {
            return null;
        }
        int colon = json.indexOf(':', k + key.length());
        int openQuote = json.indexOf('"', colon);
        int closeQuote = json.indexOf('"', openQuote + 1);
        if (openQuote < 0 || closeQuote < 0) {
            return null;
        }
        return json.substring(openQuote + 1, closeQuote);
    }

    private static String extractObject(String json, String key) {
        int k = json.indexOf(key);
        if (k < 0) {
            return null;
        }
        int brace = json.indexOf('{', k);
        if (brace < 0) {
            return null;
        }
        int depth = 0;
        boolean inStr = false;
        for (int i = brace; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"' && (i == 0 || json.charAt(i - 1) != '\\')) {
                inStr = !inStr;
            } else if (!inStr) {
                if (c == '{') depth++;
                else if (c == '}') {
                    depth--;
                    if (depth == 0) {
                        return json.substring(brace, i + 1);
                    }
                }
            }
        }
        return null;
    }

    private static String extractEnglishDescription(String cveBlock) {
        String descs = extractObject(cveBlock, "\"descriptions\"");
        if (descs == null) {
            return "See NVD record";
        }
        int i = descs.indexOf("\"lang\": \"en\"");
        if (i < 0) {
            i = descs.indexOf("\"lang\":\"en\"");
        }
        if (i < 0) {
            return "See NVD record";
        }
        return extractString(descs.substring(i), "\"value\"");
    }

    private static String extractCvssSeverity(String cveBlock) {
        String metrics = extractObject(cveBlock, "\"metrics\"");
        if (metrics == null) {
            return "Unknown";
        }
        String s = extractString(metrics, "\"baseSeverity\"");
        return s != null ? s : "Unknown";
    }

    private static double extractCvssScore(String cveBlock) {
        String metrics = extractObject(cveBlock, "\"metrics\"");
        if (metrics == null) {
            return 0;
        }
        // baseScore is a JSON NUMBER (7.5), not a quoted string.
        return extractNumber(metrics, "\"baseScore\"");
    }

    /** Extracts a JSON number appearing after "key": (unquoted). */
    private static double extractNumber(String json, String key) {
        int k = json.indexOf(key);
        if (k < 0) {
            return 0;
        }
        int colon = json.indexOf(':', k + key.length());
        if (colon < 0) {
            return 0;
        }
        int i = colon + 1;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) {
            i++;
        }
        int start = i;
        while (i < json.length() && (Character.isDigit(json.charAt(i)) || json.charAt(i) == '.'
                || json.charAt(i) == '-')) {
            i++;
        }
        try {
            return Double.parseDouble(json.substring(start, i));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static LocalDateTime extractPublished(String cveBlock) {
        String s = extractString(cveBlock, "\"published\"");
        try {
            return s != null ? LocalDateTime.parse(s.substring(0, Math.min(19, s.length()))) : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String extractCisaExploitStatus(String cveBlock) {
        String s = extractString(cveBlock, "\"cisaExploitAdd\"");
        return s != null ? "Known exploited (CISA KEV)" : "Not on CISA KEV";
    }

    private static String extractFirstReference(String cveBlock) {
        String refs = extractObject(cveBlock, "\"references\"");
        if (refs == null) {
            return "nvd.nist.gov";
        }
        String url = extractString(refs, "\"url\"");
        return url != null ? url : "nvd.nist.gov";
    }

    private static FeedResult result(List<ThreatIntelligenceEngine.ThreatIntel> items,
                                     String basis, LocalDateTime fetchedAt, String query) {
        FeedResult r = new FeedResult();
        r.items = items;
        r.feedBasis = basis;
        r.fetchedAt = fetchedAt.toString();
        r.resultsCount = items.size();
        r.query = query;
        return r;
    }

    /** Cache key hash for provenance labels / tests. */
    static String cacheKeyHash(String query) {
        return CryptoKit.sha256Hex(query).substring(0, 12);
    }
}
