package com.scamshield.backend.controller;

import com.scamshield.backend.model.User;
import com.scamshield.backend.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired(required = false)
    private JavaMailSender mailSender;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    // 1. REGISTER API
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody Map<String, String> request) {
        String email = request.getOrDefault("email", "").trim().toLowerCase();
        String password = request.getOrDefault("password", "").trim();
        String fullName = request.getOrDefault("fullName", "").trim();
        String username = request.getOrDefault("username", "").trim();

        if (email.isEmpty() || password.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Email and Password are required!"));
        }

        Optional<User> existingUser = userRepository.findByEmail(email);
        if (existingUser.isPresent()) {
            User user = existingUser.get();
            if (user.isVerified()) {
                return ResponseEntity.badRequest().body(Map.of("message", "Email is already registered and verified! Please Login."));
            } else {
                // Verified అవ్వకపోతే కొత్త OTP పంపించి డేటా అప్‌డేట్ చేస్తాం
                String newOtp = String.format("%06d", new Random().nextInt(999999));
                user.setOtp(newOtp);
                user.setPassword(passwordEncoder.encode(password));
                userRepository.save(user);
                sendOtpEmail(email, fullName.isEmpty() ? user.getFullName() : fullName, newOtp);
                return ResponseEntity.ok(Map.of("message", "Account already exists but not verified. New OTP sent to email!", "email", email));
            }
        }

        // Generate 6-digit OTP
        String otp = String.format("%06d", new Random().nextInt(999999));

        User user = new User();
        user.setFullName(fullName.isEmpty() ? "User" : fullName);
        user.setUsername(username.isEmpty() ? email.split("@")[0] : username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setOtp(otp);
        user.setVerified(false);

        userRepository.save(user);
        sendOtpEmail(email, user.getFullName(), otp);

        return ResponseEntity.ok(Map.of("message", "Registration successful! OTP sent to email.", "email", email));
    }

    // Helper method to send OTP Mail
    private void sendOtpEmail(String email, String name, String otp) {
        try {
            if (mailSender != null) {
                SimpleMailMessage mailMessage = new SimpleMailMessage();
                mailMessage.setTo(email);
                mailMessage.setSubject("ScamShield - Account OTP Verification");
                mailMessage.setText("Hello " + name + ",\n\nYour OTP for ScamShield registration is: " + otp + "\n\nThank you!");
                mailSender.send(mailMessage);
                System.out.println("OTP Mail Sent Successfully to " + email);
            }
        } catch (Exception e) {
            System.err.println("Failed to send email: " + e.getMessage());
        }
    }

    // 2. VERIFY OTP API
    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody Map<String, String> request) {
        String email = request.getOrDefault("email", "").trim().toLowerCase();
        String otp = request.getOrDefault("otp", "").trim();

        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "User not found!"));
        }

        User user = userOptional.get();

        if (user.getOtp() != null && user.getOtp().equals(otp)) {
            user.setVerified(true);
            user.setOtp(null);
            userRepository.save(user);
            return ResponseEntity.ok(Map.of("message", "OTP Verified Successfully! Please Login now."));
        } else {
            return ResponseEntity.badRequest().body(Map.of("message", "Invalid OTP! Please check your email and try again."));
        }
    }

    // 3. LOGIN API
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody Map<String, String> request) {
        String identifier = request.getOrDefault("email", "").trim().toLowerCase();
        String password = request.getOrDefault("password", "").trim();

        if (identifier.isEmpty() || password.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Email and Password are required!"));
        }

        Optional<User> userOptional = userRepository.findByEmail(identifier);
        if (userOptional.isEmpty()) {
            userOptional = userRepository.findByUsername(identifier);
        }

        if (userOptional.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "User not found! Please Register first."));
        }

        User user = userOptional.get();

        if (!user.isVerified()) {
            return ResponseEntity.badRequest().body(Map.of("message", "Account not verified! Please verify OTP first."));
        }

        boolean isMatch = passwordEncoder.matches(password, user.getPassword());

        if (!isMatch) {
            return ResponseEntity.badRequest().body(Map.of("message", "Incorrect password! Please try again."));
        }

        return ResponseEntity.ok(Map.of(
            "message", "Login Successful!",
            "data", Map.of(
                "token", "mock-jwt-token-" + UUID.randomUUID(),
                "user", Map.of(
                    "id", user.getId(),
                    "fullName", user.getFullName(),
                    "email", user.getEmail(),
                    "username", user.getUsername()
                )
            )
        ));
    }

    // 4. Debug API (Database లో ఉన్న వివరాలు బ్రౌజర్ లో చూడటానికి)
    @GetMapping("/all-users")
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(userRepository.findAll());
    }
}