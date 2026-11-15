package com.authservice.service;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import com.authservice.exception.ApiException;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class FacebookTokenVerifierTest {

    @Test
    void unconfiguredProviderCannotContactFacebook() {
        FacebookTokenVerifier verifier = new FacebookTokenVerifier("", "", RestClient.builder().build());
        assertThatThrownBy(() -> verifier.verify("not-a-real-token"))
                .isInstanceOfSatisfying(ApiException.class, error ->
                        assertThat(error.getCode()).isEqualTo("FACEBOOK_NOT_CONFIGURED"));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {
            "{\"data\":{\"is_valid\":false}}",
            "{\"data\":{\"is_valid\":true,\"app_id\":\"another-app\",\"user_id\":\"u\"}}",
            "{\"data\":{\"is_valid\":true,\"app_id\":\"app-123\"}}",
            "not-json", "{}", ""
    })
    void invalidTokenAudienceUserOrResponseCannotReachProfile(String response) {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(containsString("/debug_token")))
                .andRespond(withSuccess(response, MediaType.APPLICATION_JSON));
        FacebookTokenVerifier verifier = new FacebookTokenVerifier("app-123", "fake-secret", builder.build());
        assertThatThrownBy(() -> verifier.verify("fake-user-token"))
                .isInstanceOfSatisfying(ApiException.class, error -> {
                    assertThat(error.getCode()).isEqualTo("INVALID_TOKEN");
                    assertThat(error.getMessage()).doesNotContain("fake-secret", "fake-user-token");
                });
        server.verify();
    }

    @Test
    void missingEmailReturnsActionableCodeInsteadOfCreatingAccount() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(containsString("/debug_token"))).andRespond(withSuccess(
                "{\"data\":{\"is_valid\":true,\"app_id\":\"app-123\",\"user_id\":\"u\"}}", MediaType.APPLICATION_JSON));
        server.expect(requestTo(containsString("/u?"))).andRespond(withSuccess(
                "{\"id\":\"u\",\"name\":\"QA\"}", MediaType.APPLICATION_JSON));
        FacebookTokenVerifier verifier = new FacebookTokenVerifier("app-123", "fake-secret", builder.build());
        assertThatThrownBy(() -> verifier.verify("fake-token"))
                .isInstanceOfSatisfying(ApiException.class, error ->
                        assertThat(error.getCode()).isEqualTo("EMAIL_REQUIRED"));
        server.verify();
    }

    @Test
    void verifyParsesGraphJsonReturnedAsTextJavascript() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        MediaType graphJsonType = MediaType.parseMediaType("text/javascript;charset=UTF-8");

        server.expect(requestTo(containsString("/debug_token")))
                .andRespond(withSuccess(
                        "{\"data\":{\"is_valid\":true,\"app_id\":\"app-123\",\"user_id\":\"user-456\"}}",
                        graphJsonType));
        server.expect(requestTo(containsString("/user-456")))
                .andRespond(withSuccess(
                        "{\"id\":\"user-456\",\"name\":\"Test User\",\"email\":\"test@example.com\","
                                + "\"picture\":{\"data\":{\"url\":\"https://example.com/photo.jpg\"}}}",
                        graphJsonType));

        FacebookTokenVerifier verifier =
                new FacebookTokenVerifier("app-123", "app-secret", builder.build());
        FacebookTokenVerifier.VerifiedFacebookUser user = verifier.verify("user-access-token");

        assertThat(user.facebookSub()).isEqualTo("user-456");
        assertThat(user.email()).isEqualTo("test@example.com");
        assertThat(user.name()).isEqualTo("Test User");
        assertThat(user.pictureUrl()).isEqualTo("https://example.com/photo.jpg");
        server.verify();
    }
}
