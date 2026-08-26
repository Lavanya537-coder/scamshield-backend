package com.scamshield.backend.service;

import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class ThreatDetectorService {

    // Trusted Domains (0% Risk Guaranteed)
    private static final List<String> SAFE_DOMAINS = Arrays.asList(
        "google.com", "youtube.com", "github.com", "amazon.in", "amazon.com", 
        "microsoft.com", "wikipedia.org", "w3schools.com"
    );

    private static final List<String> SCAM_KEYWORDS = Arrays.asList(
        "urgent", "lottery", "account suspended", "verify immediately", 
        "claim reward", "kyc update", "unauthorized transaction",
        "bank alert", "winner", "cashback", "update pan"
    );

    private static final List<String> SUSPICIOUS_PATTERNS = Arrays.asList(
        "bit.ly", "tinyurl.com", "free-reward", "bank-login", "kyc-verify", "ngrok.io"
    );

    public Map<String, Object> analyzeContent(String type, String content) {
        if (content == null || content.trim().isEmpty()) {
            return buildResult(0, "Safe", Collections.singletonList("No content provided"));
        }

        String lowerText = content.toLowerCase().trim();

        // 1. Check Whitelist First
        for (String safeDomain : SAFE_DOMAINS) {
            if (lowerText.contains(safeDomain)) {
                return buildResult(0, "Safe / Legitimate Domain", Collections.singletonList("Verified Trusted Domain: " + safeDomain));
            }
        }

        int score = 0;
        List<String> detectedTriggers = new ArrayList<>();

        // 2. Keyword Threat Check
        for (String keyword : SCAM_KEYWORDS) {
            if (lowerText.contains(keyword)) {
                score += 25;
                detectedTriggers.add("Suspicious Phrase: '" + keyword + "'");
            }
        }

        // 3. Phishing Link Check
        for (String pattern : SUSPICIOUS_PATTERNS) {
            if (lowerText.contains(pattern)) {
                score += 40;
                detectedTriggers.add("High-Risk Link Pattern: " + pattern);
            }
        }

        // 4. HTTP Warning (Unencrypted)
        if (lowerText.startsWith("http://") && !lowerText.contains("localhost")) {
            score += 20;
            detectedTriggers.add("Unencrypted HTTP Protocol");
        }

        score = Math.min(score, 98);

        String threatLevel;
        if (score >= 60) {
            threatLevel = "High Risk / Critical Threat";
        } else if (score >= 30) {
            threatLevel = "Medium Risk / Suspicious";
        } else {
            threatLevel = "Low Risk / Safe Content";
        }

        if (detectedTriggers.isEmpty()) {
            detectedTriggers.add("No threat patterns or suspicious triggers found.");
        }

        return buildResult(score, threatLevel, detectedTriggers);
    }

    private Map<String, Object> buildResult(int score, String level, Object triggers) {
        Map<String, Object> response = new HashMap<>();
        response.put("riskScore", score);
        response.put("threatLevel", level);
        response.put("detectedTriggers", triggers);
        response.put("timestamp", new Date());
        return response;
    }
}