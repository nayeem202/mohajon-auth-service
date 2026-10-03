package com.authservice.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * @param accessToken user access token obtained by the app from the Facebook
 *     SDK. The server verifies it against the Graph API rather than trusting it.
 */
public record FacebookLoginRequest(
        @NotBlank String accessToken,
        String deviceId,
        String deviceName) {
}