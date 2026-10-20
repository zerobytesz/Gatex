package com.smartgateway.gateway.config;

import com.smartgateway.gateway.audit.SecurityEventService;
import com.smartgateway.gateway.threat.ThreatEngine;
import com.smartgateway.gateway.threat.ThreatProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ThreatConfig {

    @Bean
    @ConfigurationProperties(prefix = "smartgateway.threat")
    public ThreatProperties threatProperties() {
        return new ThreatProperties();
    }

    @Bean
    public ThreatEngine threatEngine(ThreatProperties properties, SecurityEventService audit) {
        ThreatEngine engine = new ThreatEngine(properties, System::currentTimeMillis);
        engine.setBlockListener(audit::persistBlock);
        return engine;
    }
}
