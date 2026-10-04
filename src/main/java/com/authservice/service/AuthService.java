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
    private final VerificationLinkService verificationLinkService;
    private final NotificationService notificationService;
    private final JwtProperties jwtProperties;
    private final GoogleIdTokenVerifier googleIdTokenVerifier;
    private final FacebookTokenVerifier facebookTokenVerifier;
    private final int maxLoginAttempts;
    private final int lockoutMinutes;
    private final String baseUrl;
    private final String mailBrandName;
    private final String supportEmail;

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
            GoogleIdTokenVerifier googleIdTokenVerifier,
            FacebookTokenVerifier facebookTokenVerifier,
            @org.springframework.beans.factory.annotation.Value("${app.security.max-login-attempts:5}") int maxLoginAttempts,
            @org.springframework.beans.factory.annotation.Value("${app.security.lockout-minutes:15}") int lockoutMinutes,
            @org.springframework.beans.factory.annotation.Value("${app.base-url:http://localhost:8080}") String baseUrl,
            VerificationLinkService verificationLinkService,
            @org.springframework.beans.factory.annotation.Value("${app.mail.brand-name:Mohajon}") String mailBrandName,
            @org.springframework.beans.factory.annotation.Value("${app.mail.support-email:support@mohajon.app}") String supportEmail) {
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
        this.facebookTokenVerifier = facebookTokenVerifier;
        this.maxLoginAttempts = maxLoginAttempts;
        this.lockoutMinutes = lockoutMinutes;
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.verificationLinkService = verificationLinkService;
        this.mailBrandName = mailBrandName;
        this.supportEmail = supportEmail;
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
    public MessageResponse verifyEmailLink(String token) {
        String email = normalizeEmail(verificationLinkService.consume(token));
        User user = findByEmail(email);
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
            throw ApiException.forbidden("ACCOUNT_DISABLED",
                    "This account is inactive. Contact your shop owner to reactivate it.");
        }
        LocalDateTime now = LocalDateTime.now();
        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(now)) {
            throw ApiException.tooManyRequests("ACCOUNT_LOCKED",
                    "Too many failed attempts. Try again in a few minutes.");
        }
        if (user.getPasswordHash() == null || !passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            registerLoginFailure(user);
            throw ApiException.unauthorized("INVALID_CREDENTIALS", "The email or password is incorrect.");
        }
        if (!user.isEmailVerified()) {
            // Only send a fresh code when none is currently pending, so cooldown
            // does not turn into an error for the user who just registered.
            if (!otpService.exists(otpKeyEmail(email))) {
                sendVerificationCode(email);
            }
            throw ApiException.forbidden("VERIFICATION_REQUIRED", "Please verify your email to sign in.");
        }
        resetLoginFailures(user);
        return completeLogin(user, request.deviceId(), request.deviceName(), ipAddress);
    }

    private void registerLoginFailure(User user) {
        int attempts = user.getFailedAttempts() + 1;
        user.setFailedAttempts(attempts);
        if (attempts >= maxLoginAttempts) {
            user.setLockedUntil(LocalDateTime.now().plusMinutes(lockoutMinutes));
            user.setFailedAttempts(0);
        }
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);
    }

    private void resetLoginFailures(User user) {
        if (user.getFailedAttempts() != 0 || user.getLockedUntil() != null) {
            user.setFailedAttempts(0);
            user.setLockedUntil(null);
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);
        }
    }

    @Transactional
    public TokenResponse refresh(RefreshRequest request) {
        RefreshToken stored = refreshTokenRepository.findByTokenHash(hash(request.refreshToken()))
                .orElseThrow(() -> ApiException.unauthorized("INVALID_REFRESH_TOKEN", "The refresh token is invalid."));

        if (stored.isRevoked()) {
            // A revoke/rotated token was replayed — likely compromise. Revoke the whole family.
            refreshTokenRepository.revokeAllForUser(stored.getUser().getId());
            throw ApiException.unauthorized("INVALID_REFRESH_TOKEN", "The refresh token is invalid. Sign in again.");
        }
        if (stored.getExpiresAt().isBefore(LocalDateTime.now())) {
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
    public MessageResponse startPhoneRecovery(PhoneRecoveryRequest request) {
        String phone = request.phone().trim();
        userRepository.findByPhoneNumber(phone)
                .filter(user -> user.getEmail() != null && !user.getEmail().isBlank())
                .ifPresent(user -> {
                    String code = otpService.generateAndStore(otpKeyPhoneRecovery(phone));
                    notificationService.sendSms(phone, "Your account recovery code is: " + code);
                });
        return new MessageResponse("If an account is eligible, a recovery code was sent to that phone.");
    }

    @Transactional
    public MessageResponse verifyPhoneRecovery(PhoneRecoveryVerifyRequest request) {
        String phone = request.phone().trim();
        otpService.verify(otpKeyPhoneRecovery(phone), request.code());
        User user = userRepository.findByPhoneNumber(phone)
                .orElseThrow(() -> ApiException.badRequest("INVALID_RECOVERY", "The recovery request is invalid."));
        if (user.getEmail() == null || user.getEmail().isBlank()) {
            throw ApiException.badRequest("NO_RECOVERY_EMAIL", "No recovery email is linked to this account.");
        }
        String email = normalizeEmail(user.getEmail());
        String resetCode = otpService.generateAndStore(otpKeyPasswordReset(email));
        notificationService.sendEmail(email, "Password reset code",
                "Your password reset code is: " + resetCode);
        return new MessageResponse("A password reset code was sent to the account email.");
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

    @Transactional
    public TokenResponse facebookLogin(FacebookLoginRequest request, String ipAddress) {
        FacebookTokenVerifier.VerifiedFacebookUser facebook =
                facebookTokenVerifier.verify(request.accessToken());
        String email = normalizeEmail(facebook.email());

        User user = userRepository.findByFacebookSub(facebook.facebookSub()).orElse(null);
        if (user == null) {
            user = userRepository.findByEmail(email).orElse(null);
        }

        boolean isNew = false;
        if (user == null) {
            user = new User();
            user.setExternalId(UUID.randomUUID().toString());
            user.setEmail(email);
            user.setFacebookSub(facebook.facebookSub());
            user.setDisplayName(facebook.name() == null || facebook.name().isBlank() ? email : facebook.name());
            user.setPhotoUrl(facebook.pictureUrl());
            user.setProvider("facebook");
            user.setStatus("ACTIVE");
            // Facebook only hands over an address it has already confirmed, so
            // unlike a plain email signup there is nothing left to verify.
            user.setEmailVerified(true);
            LocalDateTime now = LocalDateTime.now();
            user.setCreatedAt(now);
            user.setUpdatedAt(now);
            user.getRoles().add(requireRole(ROLE_OWNER));
            userRepository.save(user);
            isNew = true;
        } else {
            user.setFacebookSub(facebook.facebookSub());
            if (!user.isEmailVerified()) {
                user.setEmailVerified(true);
            }
            // A password account that later signs in with Facebook keeps its
            // password: overwriting the provider would lock the owner out of
            // the email login they may still be using.
            if (!"local".equals(user.getProvider())) {
                user.setProvider("facebook");
            }
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
        String linkToken = verificationLinkService.issue(email);
        String link = baseUrl + "/api/v1/auth/verify-email-link?token=" + linkToken;
        notificationService.sendEmail(email, "Verify your " + mailBrandName + " account",
                verificationEmail(email, code, link));
    }

    private String verificationEmail(String email, String code, String link) {
        return """
                <!doctype html>
                <html lang="en">
                <head>
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1.0">
                  <title>Verify your %s account</title>
                </head>
                <body style="margin:0;background:#f5f7f6;color:#17211d;font-family:Arial,Helvetica,sans-serif;">
                  <div style="padding:32px 12px;">
                    <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:18px;overflow:hidden;box-shadow:0 8px 28px rgba(20,45,35,.08);">
                      <tr>
                        <td style="height:7px;background:#d9a514;font-size:0;line-height:0;">&nbsp;</td>
                      </tr>
                      <tr>
                        <td style="padding:30px 34px 10px;">
                          <div style="font-size:25px;font-weight:700;letter-spacing:-.4px;color:#173d2b;">%s</div>
                          <div style="margin-top:7px;font-size:12px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#9a7410;">Account security</div>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:14px 34px 34px;">
                          <h1 style="margin:0 0 14px;font-size:25px;line-height:1.25;color:#17211d;">Verify your email address</h1>
                          <p style="margin:0 0 22px;font-size:15px;line-height:1.7;color:#52615a;">Thanks for creating a %s account. Please verify <strong style="color:#273a31;">%s</strong> to finish setting up your account.</p>
                          <div style="margin:0 0 22px;padding:20px;text-align:center;background:#fbf8ed;border:1px solid #eadcae;border-radius:14px;">
                            <div style="font-size:12px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:#8a6a13;">Your verification code is:</div>
                            <div style="margin-top:9px;font-size:32px;line-height:1.1;font-weight:800;letter-spacing:8px;color:#173d2b;">%s</div>
                            <div style="margin-top:10px;font-size:12px;color:#7a837e;">This code expires in 3 minutes.</div>
                          </div>
                          <div style="text-align:center;">
                            <a href="%s" style="display:inline-block;padding:13px 24px;background:#173d2b;color:#ffffff;text-decoration:none;border-radius:10px;font-size:14px;font-weight:700;">Verify email securely</a>
                          </div>
                          <p style="margin:22px 0 0;font-size:13px;line-height:1.6;color:#68756f;">You can also use the button above. This secure verification link expires in 24 hours and can be used only once.</p>
                          <div style="margin-top:24px;padding:15px 16px;border-left:3px solid #d9a514;background:#f8faf9;color:#596861;font-size:12px;line-height:1.65;">
                            <strong style="color:#2f4038;">Security note:</strong> If you did not create this account, you can safely ignore this email. Never share your verification code with anyone.
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:20px 34px;background:#f8faf9;border-top:1px solid #edf1ee;color:#75817b;font-size:12px;line-height:1.6;">
                          Need help? Contact <a href="mailto:%s" style="color:#496f5a;text-decoration:none;">%s</a>.<br>
                          This is an automated security email from %s. Please do not reply.
                        </td>
                      </tr>
                    </table>
                  </div>
                </body>
                </html>
                """.formatted(mailBrandName, mailBrandName, mailBrandName, email, code, link,
                supportEmail, supportEmail, mailBrandName);
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

    private static String otpKeyPhoneRecovery(String phone) {
        return "phone-recovery:" + phone;
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
