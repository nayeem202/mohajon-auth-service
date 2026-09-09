package com.authservice.controller;

import com.authservice.dto.UserResponse;
import com.authservice.entity.User;
import com.authservice.exception.ApiException;
import com.authservice.repository.UserRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/me")
    public UserResponse me(@AuthenticationPrincipal Jwt jwt) {
        return UserResponse.from(requireUser(jwt), false);
    }

    @GetMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('OWNER')")
    public UserResponse getUser(@AuthenticationPrincipal Jwt jwt, @PathVariable String userId) {
        User current = requireUser(jwt);
        User target = userRepository.findByExternalId(userId)
                .orElseThrow(() -> ApiException.notFound("USER_NOT_FOUND", "No account was found for this user."));
        if (!current.getExternalId().equals(userId)
                && !current.roleNames().contains("ADMIN")) {
            throw ApiException.forbidden("FORBIDDEN", "You cannot view this account.");
        }
        return UserResponse.from(target, false);
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public java.util.List<UserResponse> listUsers() {
        return userRepository.findAll().stream()
                .map(user -> UserResponse.from(user, false))
                .toList();
    }

    @DeleteMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(@PathVariable String userId) {
        userRepository.findByExternalId(userId)
                .ifPresent(userRepository::delete);
    }

    private User requireUser(Jwt jwt) {
        if (jwt == null) {
            throw ApiException.unauthorized("UNAUTHENTICATED", "Sign in to continue.");
        }
        return userRepository.findByExternalId(jwt.getSubject())
                .orElseThrow(() -> ApiException.unauthorized("USER_NOT_FOUND", "No account was found."));
    }
}
