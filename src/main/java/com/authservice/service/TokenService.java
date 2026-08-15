package com.authservice.service;

import com.authservice.config.JwtProperties;
import com.authservice.entity.User;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtProperties properties;

    public TokenService(JwtEncoder jwtEncoder, JwtProperties properties) {
        this.jwtEncoder = jwtEncoder;
        this.properties = properties;
    }

    public String issueAccessToken(User user) {
        Instant now = Instant.now();
        List<String> roles = user.roleNames().stream().sorted().toList();
        List<String> permissions = user.permissionNames().stream().sorted().toList();
        String displayName = user.getDisplayName();
        if (displayName == null || displayName.isBlank()) {
            displayName = user.getEmail();
        }

        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(properties.issuer())
                .issuedAt(now)
                .expiresAt(now.plus(properties.accessTtl()))
                .subject(user.getExternalId())
                .claim("email", user.getEmail())
                .claim("name", displayName)
                .claim("roles", roles)
                .claim("permissions", permissions);

        // Google accounts may not have a phone number. JWT claims cannot be null.
        if (user.getPhoneNumber() != null) {
            claims.claim("phone", user.getPhoneNumber());
        }

        return jwtEncoder.encode(
                JwtEncoderParameters.from(
                        JwsHeader.with(MacAlgorithm.HS256).build(),
                        claims.build()))
                .getTokenValue();
    }

    public Instant accessTokenExpiry() {
        return Instant.now().plus(properties.accessTtl());
    }

    public Instant refreshTokenExpiry() {
        return Instant.now().plus(properties.refreshTtl());
    }
}
