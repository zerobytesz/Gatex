package com.smartgateway.orders;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Demo order-service with object-level authorisation (OWASP API1: BOLA).
 * An order is returned only to its owner or to an ADMIN; other users get 403, which the gateway counts as a
 * failure, so enumerating other people's orders raises the caller's risk score.
 */
@RestController
@RequestMapping("/api/orders")
public class OrderController {

    public record Order(int id, String owner, String product, String status) { }

    private static final Map<String, Order> ORDERS = Map.of(
            "1001", new Order(1001, "demo", "Smart Gateway Lab Kit", "CONFIRMED"),
            "1002", new Order(1002, "admin", "API Security Course", "PROCESSING"),
            "1003", new Order(1003, "demo", "Rate Limiter Handbook", "SHIPPED"));

    @GetMapping
    public List<Order> mine(@RequestHeader(value = "X-Authenticated-User", required = false) String caller,
                            @RequestHeader(value = "X-User-Role", required = false) String role) {
        return ORDERS.values().stream()
                .filter(o -> "ADMIN".equals(role) || o.owner().equals(caller))
                .toList();
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> one(@PathVariable String id,
                                 @RequestHeader(value = "X-Authenticated-User", required = false) String caller,
                                 @RequestHeader(value = "X-User-Role", required = false) String role) {
        Order o = ORDERS.get(id);
        if (o == null) return ResponseEntity.status(404).body(Map.of("error", "Order not found", "id", id));
        if (!"ADMIN".equals(role) && !o.owner().equals(caller)) {
            return ResponseEntity.status(403).body(Map.of("error", "Forbidden", "message", "Order belongs to another user"));
        }
        return ResponseEntity.ok(Map.of("order", o, "service", "order-service"));
    }
}
