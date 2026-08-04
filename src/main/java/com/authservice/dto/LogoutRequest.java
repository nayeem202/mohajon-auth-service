package com.authservice.dto;

public record LogoutRequest(
        String refreshToken) {
}
