package com.smartgateway.gateway.config;

import com.smartgateway.gateway.audit.SecurityEventService;
import com.smartgateway.gateway.threat.ThreatEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Restores the persisted blacklist at start-up and evicts idle client profiles periodically. */
@Component
public class ThreatMaintenance implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(ThreatMaintenance.class);
    private final ThreatEngine engine;
    private final SecurityEventService audit;

    public ThreatMaintenance(ThreatEngine engine, SecurityEventService audit) {
        this.engine = engine;
        this.audit = audit;
    }

    @Override
    public void run(ApplicationArguments args) {
        var active = audit.activeBlocks();
        active.forEach(b -> engine.restoreBlock(b.clientKey(), b.blockedUntil(), b.offences()));
        if (!active.isEmpty()) log.info("Restored {} active blacklist entries", active.size());
    }

    @Scheduled(fixedDelayString = "${smartgateway.threat.eviction-interval-ms:30000}")
    public void evict() {
        int removed = engine.evictIdle();
        if (removed > 0) log.debug("Evicted {} idle client profiles", removed);
    }
}
