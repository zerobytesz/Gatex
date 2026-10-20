package com.smartgateway.gateway.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.scheduler.Schedulers;

import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Security audit trail and blacklist persistence.
 * Events are kept in memory for the dashboard and written to the database in batches off the request path,
 * so audit logging never blocks the reactive gateway threads.
 */
@Service
public class SecurityEventService {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventService.class);
    private static final int RECENT_CAPACITY = 500;
    private static final int MAX_PENDING = 20_000;

    private final JdbcTemplate jdbc;
    private final int retentionDays;
    private final Deque<SecurityEvent> recent = new ConcurrentLinkedDeque<>();
    private final AtomicInteger recentSize = new AtomicInteger();
    private final Queue<SecurityEvent> pending = new ConcurrentLinkedQueue<>();
    private final AtomicInteger pendingSize = new AtomicInteger();
    private final AtomicLong total = new AtomicLong();
    private final AtomicLong denied = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();

    public SecurityEventService(JdbcTemplate jdbc, @Value("${smartgateway.audit.retention-days:7}") int retentionDays) {
        this.jdbc = jdbc;
        this.retentionDays = retentionDays;
    }

    public void record(SecurityEvent e) {
        total.incrementAndGet();
        if (e.status() == 429) denied.incrementAndGet();
        recent.addFirst(e);
        if (recentSize.incrementAndGet() > RECENT_CAPACITY && recent.pollLast() != null) recentSize.decrementAndGet();
        if (pendingSize.get() < MAX_PENDING) {
            pending.add(e);
            pendingSize.incrementAndGet();
        } else {
            dropped.incrementAndGet();
        }
    }

    public List<SecurityEvent> recent(int limit) {
        List<SecurityEvent> out = new ArrayList<>(Math.min(limit, RECENT_CAPACITY));
        for (SecurityEvent e : recent) {
            if (out.size() >= limit) break;
            out.add(e);
        }
        return out;
    }

    public long totalEvents() { return total.get(); }
    public long deniedEvents() { return denied.get(); }
    public long droppedEvents() { return dropped.get(); }

    @Scheduled(fixedDelayString = "${smartgateway.audit.flush-interval-ms:1000}")
    public void flush() {
        List<Object[]> batch = new ArrayList<>();
        SecurityEvent e;
        while (batch.size() < 2000 && (e = pending.poll()) != null) {
            pendingSize.decrementAndGet();
            String path = e.path().length() > 500 ? e.path().substring(0, 500) : e.path();
            batch.add(new Object[]{e.timestamp(), e.clientKey(), e.ip(), e.method(), path, e.status(), e.risk(), e.level(), e.action()});
        }
        if (batch.isEmpty()) return;
        try {
            jdbc.batchUpdate("INSERT INTO security_events (ts, client_key, ip, method, path, status, risk, threat_level, action) "
                    + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", batch);
        } catch (Exception ex) {
            log.warn("Could not persist {} security events: {}", batch.size(), ex.getMessage());
        }
    }

    @Scheduled(cron = "0 0 * * * *")
    public void purgeOldEvents() {
        long cutoff = System.currentTimeMillis() - retentionDays * 86_400_000L;
        jdbc.update("DELETE FROM security_events WHERE ts < ?", cutoff);
        jdbc.update("DELETE FROM client_blacklist WHERE blocked_until < ?", System.currentTimeMillis());
    }

    /** Called by the threat engine (inside its lock), so the database write is handed off to a worker thread. */
    public void persistBlock(String key, long blockedUntil, int offences, String reason) {
        log.warn("BLOCKED {} until {} (offence #{}): {}", key, java.time.Instant.ofEpochMilli(blockedUntil), offences, reason);
        Schedulers.boundedElastic().schedule(() -> {
            try {
                jdbc.update("DELETE FROM client_blacklist WHERE client_key = ?", key);
                jdbc.update("INSERT INTO client_blacklist (client_key, blocked_until, offences, reason) VALUES (?, ?, ?, ?)",
                        key, blockedUntil, offences, reason.length() > 250 ? reason.substring(0, 250) : reason);
            } catch (Exception ex) {
                log.warn("Could not persist blacklist entry for {}: {}", key, ex.getMessage());
            }
        });
    }

    public void removeBlock(String key) {
        Schedulers.boundedElastic().schedule(() -> jdbc.update("DELETE FROM client_blacklist WHERE client_key = ?", key));
    }

    public List<BlacklistEntry> activeBlocks() {
        return jdbc.query("SELECT client_key, blocked_until, offences, reason FROM client_blacklist WHERE blocked_until > ?",
                (rs, i) -> new BlacklistEntry(rs.getString(1), rs.getLong(2), rs.getInt(3), rs.getString(4)),
                System.currentTimeMillis());
    }
}
