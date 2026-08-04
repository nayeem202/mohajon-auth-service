package com.authservice.dto;

import java.util.List;

public record UserResponse(
        String userId,
        String email,
        String phoneNumber,
        String displayName,
        String photoUrl,
        boolean emailVerified,
        boolean phoneVerified,
        String provider,
        List<String> roles,
        List<String> permissions,
        boolean isNewUser) {

    public static UserResponse from(com.authservice.entity.User user, boolean isNewUser) {
        return new UserResponse(
                user.getExternalId(),
                user.getEmail(),
                user.getPhoneNumber(),
                user.getDisplayName(),
                user.getPhotoUrl(),
                user.isEmailVerified(),
                user.isPhoneVerified(),
                user.getProvider(),
                user.roleNames().stream().sorted().toList(),
                user.permissionNames().stream().sorted().toList(),
                isNewUser);
    }
}
