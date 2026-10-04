package com.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PhoneRecoveryRequest(
        @NotBlank @Size(max = 32) String phone) {
}
