package com.authservice;

import com.authservice.entity.User;
import com.authservice.repository.RoleRepository;
import com.authservice.repository.UserRepository;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Deliberately NOT @Transactional: each HTTP request must commit its own
 * transaction so a rolled-back failed-login counter cannot hide in this test. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestNotificationConfig.class)
class AuthSecurityIntegrationTest {
    private static final String PASSWORD = "qa-password-123";
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired UserRepository users;
    @Autowired RoleRepository roles;
    @Autowired PasswordEncoder encoder;

    @Test
    void failedLoginCountersSurviveRejectedRequestsAndLockAccount() throws Exception {
        User user = owner();
        for (int attempt = 1; attempt <= 5; attempt++) {
            login(user, "wrong-password").andExpect(status().isUnauthorized());
            User persisted = users.findById(user.getId()).orElseThrow();
            if (attempt < 5) assertThat(persisted.getFailedAttempts()).isEqualTo(attempt);
            else assertThat(persisted.getLockedUntil()).isAfter(LocalDateTime.now());
        }
        login(user, PASSWORD).andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"));
    }

    @Test
    void expiredLockIsClearedBySuccessfulLogin() throws Exception {
        User user = owner();
        user.setLockedUntil(LocalDateTime.now().minusMinutes(1));
        user.setFailedAttempts(3);
        users.saveAndFlush(user);
        login(user, PASSWORD).andExpect(status().isOk());
        User persisted = users.findById(user.getId()).orElseThrow();
        assertThat(persisted.getFailedAttempts()).isZero();
        assertThat(persisted.getLockedUntil()).isNull();
    }

    @Test
    void disabledAccountCannotRefreshAnExistingSession() throws Exception {
        User user = owner();
        String token = tokens(login(user, PASSWORD)).get("refreshToken").asText();
        user = users.findById(user.getId()).orElseThrow();
        user.setStatus("DISABLED");
        users.saveAndFlush(user);
        refresh(token).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCOUNT_DISABLED"));
    }

    @Test
    void disabledAccountCannotLoginWithPassword() throws Exception {
        User user = owner();
        user.setStatus("DISABLED");
        users.saveAndFlush(user);
        login(user, PASSWORD).andExpect(status().isForbidden());
    }

    @Test
    void disabledAccountCannotBypassStatusThroughPhoneOtp() throws Exception {
        User user = owner();
        user.setPhoneNumber("+8801999900011");
        user.setStatus("DISABLED");
        users.saveAndFlush(user);
        call("/send-otp", Map.of("phone", user.getPhoneNumber())).andExpect(status().isOk());
        String code = TestNotificationConfig.lastEmailCode;
        assertThat(code).hasSize(6);
        call("/verify-otp", Map.of("phone", user.getPhoneNumber(), "code", code))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ACCOUNT_DISABLED"));
    }

    @Test
    void loggingOutOneDeviceDoesNotRevokeAnotherDevice() throws Exception {
        User user = owner();
        String first = tokens(login(user, PASSWORD)).get("refreshToken").asText();
        String second = tokens(login(user, PASSWORD)).get("refreshToken").asText();
        call("/logout", Map.of("refreshToken", first)).andExpect(status().isNoContent());
        refresh(first).andExpect(status().isUnauthorized());
        refresh(second).andExpect(status().isOk());
    }

    @Test
    void passwordResetInvalidatesOldPasswordAndRefreshTokens() throws Exception {
        User user = owner();
        String token = tokens(login(user, PASSWORD)).get("refreshToken").asText();
        call("/forgot-password", Map.of("email", user.getEmail())).andExpect(status().isOk());
        String code = TestNotificationConfig.lastEmailCode;
        assertThat(code).hasSize(6);
        call("/reset-password", Map.of("email", user.getEmail(), "code", code,
                "newPassword", "new-qa-password-123")).andExpect(status().isOk());
        refresh(token).andExpect(status().isUnauthorized());
        login(user, PASSWORD).andExpect(status().isUnauthorized());
        login(user, "new-qa-password-123").andExpect(status().isOk());
        call("/reset-password", Map.of("email", user.getEmail(), "code", code,
                "newPassword", "another-password-123")).andExpect(status().isBadRequest());
    }

    @Test
    void forgotPasswordDoesNotRevealWhetherAccountExists() throws Exception {
        User user = owner();
        String known = call("/forgot-password", Map.of("email", user.getEmail()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String unknown = call("/forgot-password", Map.of("email", UUID.randomUUID() + "@example.test"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(json.readTree(known).get("message")).isEqualTo(json.readTree(unknown).get("message"));
    }

    @Test
    void invalidRegistrationCannotCreateAccount() throws Exception {
        long before = users.count();
        call("/register", Map.of("name", "QA", "email", "invalid", "phone", "", "password", "x"))
                .andExpect(status().isBadRequest());
        assertThat(users.count()).isEqualTo(before);
    }

    private User owner() {
        User user = new User();
        user.setExternalId(UUID.randomUUID().toString());
        user.setEmail(user.getExternalId() + "@example.test");
        user.setDisplayName("QA synthetic owner");
        user.setProvider("local");
        user.setStatus("ACTIVE");
        user.setEmailVerified(true);
        user.setPasswordHash(encoder.encode(PASSWORD));
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());
        user.getRoles().add(roles.findByName("OWNER").orElseThrow());
        return users.saveAndFlush(user);
    }

    private ResultActions login(User user, String password) throws Exception {
        return call("/login", Map.of("email", user.getEmail(), "password", password,
                "deviceId", UUID.randomUUID().toString(), "deviceName", "QA"));
    }
    private ResultActions refresh(String token) throws Exception {
        return call("/refresh", Map.of("refreshToken", token));
    }
    private ResultActions call(String path, Map<String, String> body) throws Exception {
        return mvc.perform(post("/api/v1/auth" + path).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(body)));
    }
    private JsonNode tokens(ResultActions result) throws Exception {
        return json.readTree(result.andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }
}
