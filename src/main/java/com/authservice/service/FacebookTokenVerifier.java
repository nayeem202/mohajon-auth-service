package com.authservice.service;

import com.authservice.exception.ApiException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Verifies a Facebook user access token by asking Facebook's Graph API about it.
 *
 * <p>Facebook has no public JWKS for user tokens the way Google does, so the
 * token is checked with {@code /debug_token} using the app access token as proof
 * that it really was issued to this app. The same token is then used to read the
 * user's own profile, which is what supplies the email the account is keyed on.
 *
 * <p>Disabled when no app id/secret is configured, mirroring
 * {@link GoogleIdTokenVerifier}, so a deployment without Facebook configured
 * returns a clear "not configured" error instead of an opaque failure.
 */
@Service
public class FacebookTokenVerifier {

    private static final Logger log = LoggerFactory.getLogger(FacebookTokenVerifier.class);
    private static final String GRAPH = "https://graph.facebook.com/v21.0";
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final RestClient restClient;
    private final String appId;
    private final String appSecret;
    private final boolean disabled;

    @Autowired
    public FacebookTokenVerifier(
            @Value("${app.facebook.app-id:}") String appId,
            @Value("${app.facebook.app-secret:}") String appSecret) {
        // Built here rather than injected: the verifier is the only HTTP client
        // this service needs, and not depending on an auto-configured
        // RestClient.Builder keeps it constructible in every slice test.
        this(appId, appSecret, RestClient.builder().build());
    }

    FacebookTokenVerifier(String appId, String appSecret, RestClient restClient) {
        this.restClient = restClient;
        this.appId = appId;
        this.appSecret = appSecret;
        this.disabled = appId == null || appId.isBlank() || appSecret == null || appSecret.isBlank();
    }

    public VerifiedFacebookUser verify(String userAccessToken) {
        if (disabled) {
            throw ApiException.badRequest(
                    "FACEBOOK_NOT_CONFIGURED",
                    "Facebook sign-in is not configured on the server.");
        }

        JsonNode debug = getJson(
                "/debug_token",
                // input_token is passed as a query parameter, so it must be URL
                // encoded: Facebook tokens routinely contain '+' and '/'.
                UriComponentsBuilder.fromUriString(GRAPH + "/debug_token")
                        .queryParam("input_token",
                                URLEncoder.encode(userAccessToken, StandardCharsets.UTF_8))
                        .queryParam("access_token", appAccessToken())
                        .build()
                        .toUriString());
        JsonNode data = debug.path("data");
        if (!data.path("is_valid").asBoolean()) {
            String reason = data.path("error").path("message").asString("unknown reason");
            log.warn("Facebook token rejected by Graph API: {}", reason);
            throw ApiException.unauthorized("INVALID_TOKEN",
                    "The Facebook session is no longer valid. Please sign in again.");
        }
        // A token minted for a different app must not be accepted here, even
        // though Facebook considers it valid.
        String tokenAppId = data.path("app_id").asString("");
        if (!appId.equals(tokenAppId)) {
            throw ApiException.unauthorized("INVALID_TOKEN",
                    "The Facebook session belongs to a different app.");
        }
        String userId = data.path("user_id").asString("");
        if (userId.isBlank()) {
            throw ApiException.unauthorized("INVALID_TOKEN",
                    "The Facebook session did not identify a user.");
        }

        JsonNode profile = getJson(
                "/" + userId,
                UriComponentsBuilder.fromUriString(GRAPH + "/" + userId)
                        .queryParam("fields", "id,name,email,picture.type(large)")
                        .queryParam("access_token", userAccessToken)
                        .build()
                        .toUriString());

        String email = profile.path("email").asString("");
        if (email.isBlank()) {
            // Facebook only returns an email when the user granted the email
            // permission and has a confirmed address on the profile.
            throw ApiException.badRequest(
                    "EMAIL_REQUIRED",
                    "Your Facebook account did not share an email address. Please sign in with email or Google instead.");
        }

        return new VerifiedFacebookUser(
                userId,
                email,
                profile.path("name").asString(""),
                profile.path("picture").path("data").path("url").asString(""));
    }

    /**
     * App access token, built from the app id and secret. Facebook's own
     * guidance for server-to-server calls; kept server-side so the secret is
     * never shipped inside the app.
     */
    private String appAccessToken() {
        return appId + "|" + appSecret;
    }

    private JsonNode getJson(String label, String uri) {
        try {
            // Graph API may label JSON responses as text/javascript. Asking
            // RestClient to convert directly to JsonNode rejects that media
            // type, so read the body as text and parse JSON ourselves.
            String responseBody = restClient.get().uri(uri).retrieve().body(String.class);
            if (responseBody == null || responseBody.isBlank()) {
                throw ApiException.unauthorized("INVALID_TOKEN",
                        "Facebook sign-in could not be verified. Please try again.");
            }
            return JSON.readTree(responseBody);
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            // Do not log exception messages: HTTP client errors can contain
            // request URLs with the user token or app access token.
            log.warn("Facebook Graph call {} failed ({})", label, e.getClass().getSimpleName());
            throw ApiException.unauthorized("INVALID_TOKEN",
                    "Facebook sign-in could not be verified. Please try again.");
        }
    }

    public record VerifiedFacebookUser(
            String facebookSub,
            String email,
            String name,
            String pictureUrl) {}
}
