package com.scamshield.backend.controller;

import net.sourceforge.tess4j.Tesseract;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/scan")
@CrossOrigin(origins = "*")
public class ScamDetectionController {

    // 1. URL SCANNING API
    @PostMapping("/url")
    public ResponseEntity<?> scanUrl(@RequestBody Map<String, String> request) {
        String inputUrl = request.get("url");

        if (inputUrl == null || inputUrl.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "URL cannot be empty"));
        }

        String lowerUrl = inputUrl.trim().toLowerCase();

        // Direct Safe Check for Popular & Trusted Domains
        if (lowerUrl.contains("amazon") || lowerUrl.contains("google") || lowerUrl.contains("youtube") 
            || lowerUrl.contains("github") || lowerUrl.contains("linkedin") || lowerUrl.contains("microsoft") 
            || lowerUrl.contains("wikipedia") || lowerUrl.contains("diet.edu.in")) {
            
            return ResponseEntity.ok(Map.of(
                "url", inputUrl,
                "status", "SAFE",
                "riskScore", 5,
                "riskLevel", "LOW RISK",
                "message", "Verified and trusted official domain."
            ));
        }

        // Unsecured HTTP, Phishing Keywords, or Suspicious Extensions
        if (lowerUrl.startsWith("http://") || lowerUrl.contains("claim") || lowerUrl.contains("lottery") 
            || lowerUrl.contains("verify") || lowerUrl.contains("free-giftcard") || lowerUrl.contains("login-verify")
            || lowerUrl.contains("shorturl") || lowerUrl.contains("reward") || lowerUrl.contains("earn")) {
            
            return ResponseEntity.ok(Map.of(
                "url", inputUrl,
                "status", "SPAM",
                "riskScore", 88,
                "riskLevel", "HIGH RISK",
                "message", "Warning! Unsecured link or phishing pattern detected."
            ));
        }

        // Default Safe Check for Normal HTTPS Links
        return ResponseEntity.ok(Map.of(
            "url", inputUrl,
            "status", "SAFE",
            "riskScore", 15,
            "riskLevel", "SAFE",
            "message", "Legitimate and secure domain."
        ));
    }

    // 2. TEXT / MESSAGE SCANNING API
    @PostMapping({"/text", "/message"})
    public ResponseEntity<?> scanMessage(@RequestBody Map<String, String> request) {
        String message = request.getOrDefault("message", request.get("text"));

        if (message == null || message.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Message cannot be empty"));
        }

        String lowerMessage = message.trim().toLowerCase();

        // Official Transactional / OTP Messages
        boolean isOfficialOTP = (lowerMessage.contains("otp") || lowerMessage.contains("code")) 
                                && (lowerMessage.contains("amazon") || lowerMessage.contains("google") || lowerMessage.contains("bank"))
                                && !lowerMessage.contains("http://") && !lowerMessage.contains("https://");

        if (isOfficialOTP) {
            return ResponseEntity.ok(Map.of(
                "messageText", message,
                "status", "SAFE",
                "riskScore", 8,
                "riskLevel", "LOW RISK",
                "message", "Standard transactional OTP message from a trusted source."
            ));
        }

        // Expanded Spam Keywords
        List<String> spamKeywords = Arrays.asList(
            "lottery", "won", "free-giftcard", "claim", "bank-update", 
            "update-kyc", "account locked", "congratulations", "gift card", "shorturl",
            "earn", "daily", "from home", "no experience", "job", "free", "reward", "click"
        );
        boolean hasSpamKeyword = spamKeywords.stream().anyMatch(lowerMessage::contains);
        
        // Comprehensive Link & Extension Checking
        boolean hasSuspiciousLink = lowerMessage.contains("http://") || lowerMessage.contains("https://")
                                    || lowerMessage.contains(".xyz") || lowerMessage.contains(".net") 
                                    || lowerMessage.contains(".com") || lowerMessage.contains(".org")
                                    || lowerMessage.contains("shorturl");

        if (hasSpamKeyword || hasSuspiciousLink) {
            return ResponseEntity.ok(Map.of(
                "messageText", message,
                "status", "SPAM",
                "riskScore", 88,
                "riskLevel", "HIGH RISK",
                "message", "Warning! Message contains scam keywords or suspicious links."
            ));
        }

        // Normal Clean Messages
        return ResponseEntity.ok(Map.of(
            "messageText", message,
            "status", "SAFE",
            "riskScore", 12,
            "riskLevel", "SAFE",
            "message", "This message appears clean and safe."
        ));
    }

    // 3. OCR IMAGE SCANNING API
    @PostMapping("/image")
    public ResponseEntity<?> scanImage(@RequestParam("file") MultipartFile file) {
        if (file == null || file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Please upload a valid image file."));
        }

        String contentType = file.getContentType();
        if (contentType == null || !contentType.startsWith("image/")) {
            return ResponseEntity.ok(Map.of(
                "status", "INVALID",
                "riskLevel", "HIGH RISK",
                "message", "Uploaded file is not a valid image."
            ));
        }

        String extractedText = "";
        File cleanPngFile = null;
        boolean ocrSuccess = false;

        try {
            // Read Image & Convert to Clean PNG
            BufferedImage rawImage = ImageIO.read(file.getInputStream());
            if (rawImage == null) {
                return ResponseEntity.ok(Map.of(
                    "fileName", file.getOriginalFilename(),
                    "extractedText", "Unsupported or corrupted image file.",
                    "status", "UNCERTAIN",
                    "riskScore", 50,
                    "riskLevel", "MEDIUM RISK",
                    "message", "Image format invalid."
                ));
            }

            BufferedImage cleanImage = new BufferedImage(
                rawImage.getWidth(), 
                rawImage.getHeight(), 
                BufferedImage.TYPE_INT_RGB
            );
            cleanImage.createGraphics().drawImage(rawImage, 0, 0, null);

            cleanPngFile = File.createTempFile("ocr_clean_", ".png");
            ImageIO.write(cleanImage, "png", cleanPngFile);

            // Dynamic Absolute Datapath Configuration
            try {
                Tesseract tesseract = new Tesseract();

                String userDir = System.getProperty("user.dir");
                File tessDataFolder = new File(userDir, "tessdata");

                // Check nesting paths dynamically
                if (!tessDataFolder.exists() || !new File(tessDataFolder, "eng.traineddata").exists()) {
                    tessDataFolder = new File(userDir, "backend/tessdata");
                }
                if (!tessDataFolder.exists() || !new File(tessDataFolder, "eng.traineddata").exists()) {
                    tessDataFolder = new File(userDir, "backend/backend/tessdata");
                }

                if (tessDataFolder.exists() && new File(tessDataFolder, "eng.traineddata").exists()) {
                    tesseract.setDatapath(tessDataFolder.getAbsolutePath());
                    System.out.println("TESSDATA SUCCESS: Loaded from " + tessDataFolder.getAbsolutePath());
                } else {
                    System.err.println("TESSDATA WARNING: Dynamic path failed, defaulting to 'tessdata'");
                    tesseract.setDatapath("tessdata");
                }

                extractedText = tesseract.doOCR(cleanPngFile);
                if (extractedText != null && !extractedText.trim().isEmpty()) {
                    ocrSuccess = true;
                }
            } catch (Throwable t) {
                System.err.println("OCR Exception: " + t.getMessage());
                ocrSuccess = false;
            }

            if (!ocrSuccess || extractedText.trim().length() < 3) {
                return ResponseEntity.ok(Map.of(
                    "fileName", file.getOriginalFilename(),
                    "extractedText", "No text could be extracted.",
                    "status", "UNCERTAIN",
                    "riskScore", 50,
                    "riskLevel", "MEDIUM RISK",
                    "message", "OCR Failed to read text. Check tessdata/eng.traineddata file placement."
                ));
            }

            String lowerExtractedText = extractedText.toLowerCase().replaceAll("\\s+", " ");

            List<String> scamKeywords = Arrays.asList(
                "congratulations", "selected to receive", "gift card", "amazon",
                "claim", "24 hours", "shorturl", "click the link", "lottery", "won",
                "payment", "qr", "verify your eligibility", "reward", "spam", "giftcard",
                "earn", "daily", "from home", "no experience", "job", "free", "click", "selected"
            );

            boolean hasSpamKeyword = scamKeywords.stream().anyMatch(lowerExtractedText::contains);

            boolean hasSuspiciousLink = lowerExtractedText.contains("http://") 
                                        || lowerExtractedText.contains("https://") 
                                        || lowerExtractedText.contains(".at")
                                        || lowerExtractedText.contains("shorturl")
                                        || lowerExtractedText.contains(".com")
                                        || lowerExtractedText.contains(".net")
                                        || lowerExtractedText.contains(".xyz");

            if (hasSpamKeyword || hasSuspiciousLink) {
                return ResponseEntity.ok(Map.of(
                    "fileName", file.getOriginalFilename(),
                    "extractedText", extractedText.length() > 100 ? extractedText.substring(0, 100) + "..." : extractedText,
                    "status", "SPAM",
                    "riskScore", 90,
                    "riskLevel", "HIGH RISK",
                    "message", "Scam detected inside image content!"
                ));
            }

            return ResponseEntity.ok(Map.of(
                "fileName", file.getOriginalFilename(),
                "extractedText", extractedText,
                "status", "CLEAN",
                "riskScore", 10,
                "riskLevel", "SAFE",
                "message", "No suspicious scam patterns found in the image text."
            ));

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Failed to process image: " + e.getMessage()));
        } finally {
            if (cleanPngFile != null && cleanPngFile.exists()) {
                cleanPngFile.delete();
            }
        }
    }
}