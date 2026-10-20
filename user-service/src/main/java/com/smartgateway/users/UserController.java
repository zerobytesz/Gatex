package com.smartgateway.users;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Demo user-service. Only reachable through the gateway, which forwards the verified identity
 * in X-Authenticated-User. Unknown ids return a real 404 so the gateway can learn from failures.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private static final Map<String, Map<String, Object>> USERS = Map.of(
            "1", Map.of("id", 1, "name", "Demo User", "email", "demo@smartgateway.local", "role", "USER"),
            "2", Map.of("id", 2, "name", "Security Admin", "email", "admin@smartgateway.local", "role", "ADMIN"));

    @GetMapping
    public List<Map<String, Object>> all() {
        return List.copyOf(USERS.values());
    }

    @GetMapping("/{id}")
    public ResponseEntity<Map<String, Object>> one(@PathVariable String id,
                                                   @RequestHeader(value = "X-Authenticated-User", required = false) String caller) {
        Map<String, Object> u = USERS.get(id);
        if (u == null) return ResponseEntity.status(404).body(Map.of("error", "User not found", "id", id));
        return ResponseEntity.ok(Map.of("user", u, "service", "user-service", "requestedBy", caller == null ? "unknown" : caller));
    }

    @GetMapping("/me")
    public Map<String, Object> me(@RequestHeader(value = "X-Authenticated-User", required = false) String caller) {
        return Map.of("username", caller == null ? "unknown" : caller, "service", "user-service");
    }
}
