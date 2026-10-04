package com.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PhoneRecoveryVerifyRequest(
        @NotBlank @Size(max = 32) String phone,
        @NotBlank String code) {
}
