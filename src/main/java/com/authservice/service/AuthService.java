package com.authservice.service;

import com.authservice.config.NotificationService;
import com.authservice.config.JwtProperties;
import com.authservice.dto.*;
import com.authservice.entity.LoginSession;
import com.authservice.entity.RefreshToken;
import com.authservice.entity.Role;
import com.authservice.entity.User;
import com.authservice.exception.ApiException;
import com.authservice.repository.LoginSessionRepository;
import com.authservice.repository.RefreshTokenRepository;
import com.authservice.repository.RoleRepository;
import com.authservice.repository.UserRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class AuthService {

    private static final String ROLE_OWNER = "OWNER";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final LoginSessionRepository loginSessionRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final OtpService otpService;
    private final NotificationService notificationService;
    private final JwtProperties jwtProperties;
    private final GoogleIdTokenVerifier googleIdTokenVerifier;

    public AuthService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            RefreshTokenRepository refreshTokenRepository,
            LoginSessionRepository loginSessionRepository,
            PasswordEncoder passwordEncoder,
            TokenService tokenService,
            OtpService otpService,
            NotificationService notificationService,
            JwtProperties jwtProperties,
            GoogleIdTokenVerifier googleIdTokenVerifier) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.loginSessionRepository = loginSessionRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.otpService = otpService;
        this.notificationService = notificationService;
        this.jwtProperties = jwtProperties;
        this.googleIdTokenVerifier = googleIdTokenVerifier;
    }

    @Transactional
    public MessageResponse register(RegisterRequest request) {
        String email = normalizeEmail(request.email());
        String phone = request.phone().trim();

        if (userRepository.existsByEmail(email)) {
            throw ApiException.conflict("EMAIL_ALREADY_EXISTS", "This email already has an account.");
        }
        if (userRepository.existsByPhoneNumber(phone)) {
            throw ApiException.conflict("PHONE_ALREADY_EXISTS", "This phone number already has an account.");
        }

        User user = new User();
        user.setExternalId(UUID.randomUUID().toString());
        user.setEmail(email);
        user.setPhoneNumber(phone);
        user.setDisplayName(request.name().trim());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setProvider("local");
        user.setStatus("ACTIVE");
        LocalDateTime now = LocalDateTime.now();
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        user.getRoles().add(requireRole(ROLE_OWNER));

        try {
            userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            throw ApiException.conflict("EMAIL_ALREADY_EXISTS", "This email or phone already has an account.");
        }

        sendVerificationCode(email);
        return new MessageResponse("Account created. A verification code was sent to your email.");
    }

    @Transactional
    public MessageResponse verifyEmail(VerifyEmailRequest request) {
        String email = normalizeEmail(request.email());
        User user = findByEmail(email);
        otpService.verify(otpKeyEmail(email), request.code());
        user.setEmailVerified(true);
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);
        return new MessageResponse("Email verified. You can now sign in.");
    }

    @Transactional
    public MessageResponse resendVerification(ResendVerificationRequest request) {
        String email = normalizeEmail(request.email());
        User user = findByEmail(email);
        if (user.isEmailVerified()) {
            return new MessageResponse("Email is already verified.");
        }
        sendVerificationCode(email);
        return new MessageResponse("A fresh verification code was sent to your email.");
    }

    @Transactional
    public TokenResponse login(LoginRequest request, String ipAddress) {
        String email = normalizeEmail(request.email());
        User user = findByEmail(email);
        if (!user.isActive()) {
            throw ApiException.forbidden("ACCOUNT_DISABLED", "This account has been disabled.");
        }
        if (user.getPasswordHash() == null || !passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw ApiException.unauthorized("INVALID_CREDENTIALS", "The email or password is incorrect.");
        }
        if (!user.isEmailVerified()) {
            sendVerificationCode(email);
            throw ApiException.forbidden("VERIFICATION_REQUIRED", "Please verify your email first. A fresh code was sent.");
        }
        return completeLogin(user, request.deviceId(), request.deviceName(), ipAddress);
    }

    @Transactional
    public TokenResponse refresh(RefreshRequest request) {
        RefreshToken stored = refreshTokenRepository.findByTokenHash(hash(request.refreshToken()))
                .orElseThrow(() -> ApiException.unauthorized("INVALID_REFRESH_TOKEN", "The refresh token is invalid."));

        if (stored.isRevoked() || stored.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw ApiException.unauthorized("INVALID_REFRESH_TOKEN", "The refresh token has expired. Sign in again.");
        }

        User user = stored.getUser();
        stored.setRevoked(true);
        refreshTokenRepository.save(stored);
        return issueTokens(user, stored.getDeviceId(), stored.getUserAgent(), null);
    }

    @Transactional
    public void logout(String refreshTokenValue) {
        if (refreshTokenValue == null || refreshTokenValue.isBlank()) {
            return;
        }
        refreshTokenRepository.findByTokenHash(hash(refreshTokenValue))
                .ifPresent(token -> {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                });
    }

    @Transactional
    public void logoutAll(String externalId) {
        userRepository.findByExternalId(externalId)
                .ifPresent(user -> refreshTokenRepository.revokeAllForUser(user.getId()));
    }

    @Transactional
    public MessageResponse forgotPassword(ForgotPasswordRequest request) {
        String email = normalizeEmail(request.email());
        // Do not leak whether the email exists.
        userRepository.findByEmail(email).ifPresent(user -> {
            String code = otpService.generateAndStore(otpKeyPasswordReset(email));
            notificationService.sendEmail(email, "Password reset code",
                    "Your password reset code is: " + code);
        });
        return new MessageResponse("If an account exists, a reset code was sent to the email.");
    }

    @Transactional
    public MessageResponse resetPassword(ResetPasswordRequest request) {
        String email = normalizeEmail(request.email());
        User user = findByEmail(email);
        otpService.verify(otpKeyPasswordReset(email), request.code());
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);
        refreshTokenRepository.revokeAllForUser(user.getId());
        return new MessageResponse("Password updated. You can now sign in.");
    }

    @Transactional
    public MessageResponse changePassword(String externalId, ChangePasswordRequest request) {
        User user = userRepository.findByExternalId(externalId)
                .orElseThrow(() -> ApiException.unauthorized("USER_NOT_FOUND", "No account was found."));
        if (user.getPasswordHash() == null || !passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
            throw ApiException.unauthorized("INVALID_CREDENTIALS", "The current password is incorrect.");
        }
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);
        return new MessageResponse("Password updated.");
    }

    @Transactional
    public MessageResponse sendOtp(SendOtpRequest request) {
        String phone = request.phone().trim();
        String code = otpService.generateAndStore(otpKeyPhone(phone));
        notificationService.sendSms(phone, "Your verification code is: " + code);
        return new MessageResponse("A verification code was sent to your phone.");
    }

    @Transactional
    public TokenResponse verifyOtp(VerifyOtpRequest request, String ipAddress) {
        String phone = request.phone().trim();
        otpService.verify(otpKeyPhone(phone), request.code());

        User user = userRepository.findByPhoneNumber(phone).orElse(null);
        boolean isNew = false;
        if (user == null) {
            user = new User();
            user.setExternalId(UUID.randomUUID().toString());
            user.setPhoneNumber(phone);
            user.setDisplayName(request.displayName() == null || request.displayName().isBlank()
                    ? phone
                    : request.displayName().trim());
            user.setProvider("local");
            user.setStatus("ACTIVE");
            user.setPhoneVerified(true);
            LocalDateTime now = LocalDateTime.now();
            user.setCreatedAt(now);
            user.setUpdatedAt(now);
            user.getRoles().add(requireRole(ROLE_OWNER));
            userRepository.save(user);
            isNew = true;
        } else {
            user.setPhoneVerified(true);
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);
        }
        return issueTokens(user, request.deviceId(), request.deviceName(), ipAddress, isNew);
    }

    @Transactional
    public TokenResponse googleLogin(GoogleLoginRequest request, String ipAddress) {
        GoogleIdTokenVerifier.VerifiedGoogleUser google = googleIdTokenVerifier.verify(request.idToken());
        String email = normalizeEmail(google.email());

        User user = userRepository.findByGoogleSub(google.googleSub()).orElse(null);
        if (user == null) {
            user = userRepository.findByEmail(email).orElse(null);
        }

        boolean isNew = false;
        if (user == null) {
            user = new User();
            user.setExternalId(UUID.randomUUID().toString());
            user.setEmail(email);
            user.setGoogleSub(google.googleSub());
            user.setDisplayName(google.name() == null || google.name().isBlank() ? email : google.name());
            user.setPhotoUrl(google.pictureUrl());
            user.setProvider("google");
            user.setStatus("ACTIVE");
            user.setEmailVerified(true);
            LocalDateTime now = LocalDateTime.now();
            user.setCreatedAt(now);
            user.setUpdatedAt(now);
            user.getRoles().add(requireRole(ROLE_OWNER));
            userRepository.save(user);
            isNew = true;
        } else {
            user.setGoogleSub(google.googleSub());
            user.setEmailVerified(true);
            user.setProvider("google");
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);
        }
        return issueTokens(user, request.deviceId(), request.deviceName(), ipAddress, isNew);
    }

    private TokenResponse completeLogin(User user, String deviceId, String deviceName, String ipAddress) {
        user.setLastLoginAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);
        recordLoginSession(user, deviceId, deviceName, ipAddress);
        return issueTokens(user, deviceId, deviceName, ipAddress, false);
    }

    private TokenResponse issueTokens(User user, String deviceId, String deviceName, String ipAddress) {
        return issueTokens(user, deviceId, deviceName, ipAddress, false);
    }

    private TokenResponse issueTokens(User user, String deviceId, String deviceName, String ipAddress, boolean isNew) {
        String accessToken = tokenService.issueAccessToken(user);

        String refreshValue = UUID.randomUUID().toString().replace("-", "");
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setTokenHash(hash(refreshValue));
        refreshToken.setUser(user);
        refreshToken.setDeviceId(deviceId);
        refreshToken.setUserAgent(deviceName);
        refreshToken.setExpiresAt(LocalDateTime.ofInstant(tokenService.refreshTokenExpiry(), ZoneOffset.UTC));
        refreshToken.setRevoked(false);
        refreshToken.setCreatedAt(LocalDateTime.now());
        refreshTokenRepository.save(refreshToken);

        return new TokenResponse(
                accessToken,
                refreshValue,
                jwtProperties.accessTtl().toSeconds(),
                jwtProperties.refreshTtl().toSeconds(),
                "Bearer",
                UserResponse.from(user, isNew));
    }

    private void recordLoginSession(User user, String deviceId, String deviceName, String ipAddress) {
        LoginSession session = new LoginSession();
        session.setSessionId(UUID.randomUUID().toString());
        session.setUser(user);
        session.setDeviceId(deviceId);
        session.setDeviceName(deviceName);
        session.setIpAddress(ipAddress);
        session.setLastLoginAt(LocalDateTime.now());
        session.setCreatedAt(LocalDateTime.now());
        loginSessionRepository.save(session);
    }

    private void sendVerificationCode(String email) {
        String code = otpService.generateAndStore(otpKeyEmail(email));
        notificationService.sendEmail(email, "Verify your email",
                "Your verification code is: " + code);
    }

    private User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> ApiException.unauthorized("USER_NOT_FOUND", "No account was found for this email."));
    }

    private Role requireRole(String name) {
        return roleRepository.findByName(name)
                .orElseThrow(() -> new IllegalStateException("Role not seeded: " + name));
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }

    private static String otpKeyEmail(String email) {
        return "email:" + email;
    }

    private static String otpKeyPhone(String phone) {
        return "phone:" + phone;
    }

    private static String otpKeyPasswordReset(String email) {
        return "reset:" + email;
    }

    private static String hash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
