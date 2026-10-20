package com.smartgateway.gateway.auth;

import com.smartgateway.gateway.security.JwtService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Login and registration. Failed logins return 401; IpThreatWebFilter records them as failed-login
 * evidence for the client IP, which is how credential stuffing / brute force is detected and blocked.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9_.-]{3,32}$");

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;

    public AuthController(UserRepository users, PasswordEncoder encoder, JwtService jwt) {
        this.users = users;
        this.encoder = encoder;
        this.jwt = jwt;
    }

    public record Credentials(String username, String password) { }

    @PostMapping("/login")
    public Mono<ResponseEntity<Map<String, Object>>> login(@RequestBody Credentials body) {
        return Mono.fromCallable(() -> {
            if (body == null || body.username() == null || body.password() == null) {
                return error(HttpStatus.BAD_REQUEST, "username and password are required");
            }
            var account = users.find(body.username());
            if (account.isEmpty() || !encoder.matches(body.password(), account.get().passwordHash())) {
                return error(HttpStatus.UNAUTHORIZED, "Invalid credentials");
            }
            UserAccount u = account.get();
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("token", jwt.issue(u.username(), u.role()));
            ok.put("tokenType", "Bearer");
            ok.put("username", u.username());
            ok.put("role", u.role());
            ok.put("expiresInSeconds", jwt.ttlSeconds());
            return ResponseEntity.ok(ok);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    @PostMapping("/register")
    public Mono<ResponseEntity<Map<String, Object>>> register(@RequestBody Credentials body) {
        return Mono.fromCallable(() -> {
            if (body == null || body.username() == null || !USERNAME.matcher(body.username()).matches()) {
                return error(HttpStatus.BAD_REQUEST, "username must be 3-32 characters: letters, digits, . _ -");
            }
            if (body.password() == null || body.password().length() < 8) {
                return error(HttpStatus.BAD_REQUEST, "password must be at least 8 characters");
            }
            boolean created = users.create(body.username(), encoder.encode(body.password()), "USER");
            if (!created) return error(HttpStatus.CONFLICT, "username already exists");
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("message", "Account created");
            ok.put("username", body.username());
            return ResponseEntity.status(HttpStatus.CREATED).body(ok);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private static ResponseEntity<Map<String, Object>> error(HttpStatus status, String message) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("error", status.getReasonPhrase());
        m.put("message", message);
        return ResponseEntity.status(status).body(m);
    }
}
