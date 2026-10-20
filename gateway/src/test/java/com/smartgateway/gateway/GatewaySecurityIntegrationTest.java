package com.smartgateway.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Starts the real gateway (H2 database) and checks authentication and authorisation end to end.
 * {@code @AutoConfigureObservability} is needed because Spring Boot disables metrics export (and with it the
 * /actuator/prometheus endpoint) in tests by default.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@AutoConfigureObservability
class GatewaySecurityIntegrationTest {

    @Autowired
    private WebTestClient client;

    private String token(String user, String password) {
        Map<?, ?> body = client.post().uri("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("username", user, "password", password))
                .exchange().expectStatus().isOk()
                .expectBody(Map.class).returnResult().getResponseBody();
        assertNotNull(body);
        return (String) body.get("token");
    }

    @Test
    void loginIssuesJwt() {
        assertNotNull(token("demo", "password123"));
    }

    @Test
    void wrongPasswordIsRejected() {
        client.post().uri("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("username", "demo", "password", "wrong-password"))
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    void protectedRouteRequiresJwt() {
        client.get().uri("/api/users/1").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void invalidJwtIsRejected() {
        client.get().uri("/api/users/1").header("Authorization", "Bearer not.a.valid.token")
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    void adminApiRequiresAdminRole() {
        String user = token("demo", "password123");
        client.get().uri("/api/admin/overview").header("Authorization", "Bearer " + user)
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void adminCanReadOverviewAndEvents() {
        String admin = token("admin", "admin123");
        client.get().uri("/api/admin/overview").header("Authorization", "Bearer " + admin)
                .exchange().expectStatus().isOk().expectBody().jsonPath("$.trackedClients").exists();
        client.get().uri("/api/admin/events").header("Authorization", "Bearer " + admin)
                .exchange().expectStatus().isOk();
    }

    @Test
    void registrationValidatesInput() {
        client.post().uri("/auth/register").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("username", "x", "password", "short"))
                .exchange().expectStatus().isBadRequest();
        client.post().uri("/auth/register").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("username", "newuser", "password", "long-enough-pass"))
                .exchange().expectStatus().isCreated();
    }

    @Test
    void healthAndPrometheusArePublic() {
        client.get().uri("/actuator/health").exchange().expectStatus().isOk();
        client.get().uri("/actuator/prometheus").exchange().expectStatus().isOk();
    }
}
