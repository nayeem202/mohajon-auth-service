package com.authservice.service;

import com.authservice.exception.ApiException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URL;
import java.time.Instant;
import java.util.Set;

/**
 * Verifies Google ID tokens using Google's public JWKS (cached by RemoteJWKSet).
 * Google ID tokens are signed with RS256 only.
 */
@Service
public class GoogleIdTokenVerifier {

    private static final Logger log = LoggerFactory.getLogger(GoogleIdTokenVerifier.class);
    private static final Set<String> ALLOWED_ISSUERS = Set.of("accounts.google.com", "https://accounts.google.com");

    private final ConfigurableJWTProcessor<SecurityContext> processor;
    private final String expectedAudience;
    private final boolean disabled;

    public GoogleIdTokenVerifier(
            @Value("${app.google.client-id:}") String expectedAudience) throws Exception {
        this.expectedAudience = expectedAudience;
        this.disabled = expectedAudience == null || expectedAudience.isBlank();

        JWKSource<SecurityContext> jwkSource =
                new RemoteJWKSet<>(new URL("https://www.googleapis.com/oauth2/v3/certs"));
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
        this.processor = new DefaultJWTProcessor<>();
        this.processor.setJWSKeySelector(keySelector);
    }

    public VerifiedGoogleUser verify(String idToken) {
        if (disabled) {
            throw ApiException.badRequest("GOOGLE_NOT_CONFIGURED", "Google sign-in is not configured on the server.");
        }
        try {
            JWTClaimsSet claims = processor.process(idToken, null);
            String issuer = claims.getIssuer();
            if (!ALLOWED_ISSUERS.contains(issuer)) {
                throw ApiException.unauthorized("INVALID_TOKEN", "The Google token was issued by an unknown party.");
            }
            if (!expectedAudience.equals(claims.getAudience().stream().findFirst().orElse(null))) {
                throw ApiException.unauthorized("INVALID_TOKEN", "The Google token audience does not match.");
            }
            Instant expiry = claims.getExpirationTime() == null
                    ? Instant.now().minusSeconds(1)
                    : claims.getExpirationTime().toInstant();
            if (expiry.isBefore(Instant.now())) {
                throw ApiException.unauthorized("INVALID_TOKEN", "The Google token has expired.");
            }
            String email = claims.getStringClaim("email");
            if (email == null || email.isBlank()) {
                throw ApiException.unauthorized("INVALID_TOKEN", "The Google token has no email.");
            }
            if (claims.getBooleanClaim("email_verified") != Boolean.TRUE) {
                throw ApiException.unauthorized("EMAIL_NOT_VERIFIED", "Please verify your Gmail account email first.");
            }
            return new VerifiedGoogleUser(
                    claims.getSubject(),
                    email,
                    claims.getStringClaim("name"),
                    claims.getStringClaim("picture"));
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Google ID token verification failed: {}", e.getMessage());
            throw ApiException.unauthorized("INVALID_TOKEN", "The Google token could not be verified.");
        }
    }

    public record VerifiedGoogleUser(String googleSub, String email, String name, String pictureUrl) {}
}
