package com.smartgateway.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** Repeated failed logins from one IP must end in a temporary block (HTTP 429). Uses its own context and database so the persisted block cannot affect other tests. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.datasource.url=jdbc:h2:mem:stuffingtest;MODE=MySQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1")
@AutoConfigureWebTestClient
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class CredentialStuffingIntegrationTest {

    @Autowired
    private WebTestClient client;

    @Test
    void repeatedFailedLoginsAreBlocked() {
        boolean blocked = false;
        for (int i = 0; i < 20 && !blocked; i++) {
            int status = client.post().uri("/auth/login").contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("username", "demo", "password", "guess-" + i))
                    .exchange().returnResult(String.class).getStatus().value();
            blocked = status == 429;
        }
        assertTrue(blocked, "credential stuffing from one IP should be blocked");
    }
}
