package com.authservice.controller;

import com.authservice.dto.*;
import com.authservice.exception.ApiException;
import com.authservice.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final String brandName;

    public AuthController(AuthService authService,
                          @Value("${app.mail.brand-name:Mohajon}") String brandName) {
        this.authService = authService;
        this.brandName = brandName;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public MessageResponse register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    @PostMapping("/verify-email")
    public MessageResponse verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        return authService.verifyEmail(request);
    }

    @GetMapping(value = "/verify-email-link", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> verifyEmailLink(@RequestParam(required = false) String token) {
        try {
            authService.verifyEmailLink(token);
            return activationPage(HttpStatus.OK, true);
        } catch (ApiException exception) {
            // A browser visit must not show the API's JSON error payload. The
            // same safe text covers expired, invalid and already-used links.
            return activationPage(HttpStatus.GONE, false);
        }
    }

    private ResponseEntity<String> activationPage(HttpStatus status, boolean activated) {
        String safeBrand = escapeHtml(brandName == null || brandName.isBlank() ? "Mohajon" : brandName);
        String title = activated ? "Account activated" : "Verification link unavailable";
        String icon = activated ? "✓" : "!";
        String lead = activated
                ? "Your email address has been verified successfully."
                : "This verification link has expired, was already used, or is not valid.";
        String detail = activated
                ? "You can now return to the " + safeBrand + " app and sign in with your email and password."
                : "Open the " + safeBrand + " app and request a new verification email to continue.";
        String state = activated ? "success" : "expired";
        String html = """
                <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
                <meta name="robots" content="noindex,nofollow"><title>%s · %s</title>
                <style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:linear-gradient(145deg,#fff8d5,#fffdf6 50%%,#eff7e5);color:#2f3028;font-family:Inter,Arial,sans-serif}.card{width:min(440px,calc(100%% - 40px));box-sizing:border-box;background:#fffdf7;border:1px solid #eadfae;border-radius:28px;padding:38px 30px;text-align:center;box-shadow:0 22px 65px rgba(76,59,5,.14)}.mark{width:64px;height:64px;margin:0 auto 18px;border-radius:22px;display:grid;place-items:center;font-size:34px;font-weight:800}.success .mark{background:#e8f6ec;color:#047857}.expired .mark{background:#fff0e2;color:#ea580c}h1{margin:0;font-size:25px;letter-spacing:-.5px}p{margin:13px 0 0;color:#686f61;font-size:15px;line-height:1.58}.note{margin-top:24px;padding:13px 15px;border-radius:14px;background:#fff8d5;color:#775900;font-size:13px;font-weight:650}.brand{margin-top:27px;color:#a37a00;font-size:12px;font-weight:800;letter-spacing:1.4px;text-transform:uppercase}</style></head>
                <body><main class="card %s"><div class="mark">%s</div><h1>%s</h1><p>%s</p><p>%s</p><div class="note">%s</div><div class="brand">%s</div></main></body></html>
                """.formatted(title, safeBrand, state, icon, title, lead, detail,
                activated ? "You may close this page and return to the app." : "For your security, each verification link can be used only once.", safeBrand);
        return ResponseEntity.status(status).contentType(MediaType.TEXT_HTML)
                .cacheControl(CacheControl.noStore()).body(html);
    }

    private static String escapeHtml(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    @PostMapping("/resend-verification")
    public MessageResponse resendVerification(@Valid @RequestBody ResendVerificationRequest request) {
        return authService.resendVerification(request);
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
        return authService.login(request, clientIp(http));
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request) {
        return authService.refresh(request);
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@RequestBody(required = false) LogoutRequest request) {
        authService.logout(request == null ? null : request.refreshToken());
    }

    @PostMapping("/forgot-password")
    public MessageResponse forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        return authService.forgotPassword(request);
    }

    @PostMapping("/reset-password")
    public MessageResponse resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        return authService.resetPassword(request);
    }

    @PostMapping("/change-password")
    public MessageResponse changePassword(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody ChangePasswordRequest request) {
        return authService.changePassword(userId(jwt), request);
    }

    @PostMapping("/send-otp")
    public MessageResponse sendOtp(@Valid @RequestBody SendOtpRequest request) {
        return authService.sendOtp(request);
    }

    @PostMapping("/verify-otp")
    public TokenResponse verifyOtp(@Valid @RequestBody VerifyOtpRequest request, HttpServletRequest http) {
        return authService.verifyOtp(request, clientIp(http));
    }

    @PostMapping("/phone-recovery/start")
    public MessageResponse startPhoneRecovery(@Valid @RequestBody PhoneRecoveryRequest request) {
        return authService.startPhoneRecovery(request);
    }

    @PostMapping("/phone-recovery/verify")
    public MessageResponse verifyPhoneRecovery(@Valid @RequestBody PhoneRecoveryVerifyRequest request) {
        return authService.verifyPhoneRecovery(request);
    }

    @PostMapping("/google")
    public TokenResponse googleLogin(@Valid @RequestBody GoogleLoginRequest request, HttpServletRequest http) {
        return authService.googleLogin(request, clientIp(http));
    }

    @PostMapping("/facebook")
    public TokenResponse facebookLogin(@Valid @RequestBody FacebookLoginRequest request, HttpServletRequest http) {
        return authService.facebookLogin(request, clientIp(http));
    }

    @PostMapping("/logout-all")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logoutAll(@AuthenticationPrincipal Jwt jwt) {
        authService.logoutAll(userId(jwt));
    }

    private String userId(Jwt jwt) {
        if (jwt == null) {
            throw com.authservice.exception.ApiException.unauthorized(
                    "UNAUTHENTICATED", "Sign in to continue.");
        }
        return jwt.getSubject();
    }

    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
