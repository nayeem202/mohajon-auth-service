package com.authservice.dto;

import jakarta.validation.constraints.NotBlank;

public record GoogleLoginRequest(
        @NotBlank String idToken,
        String deviceId,
        String deviceName) {
}
