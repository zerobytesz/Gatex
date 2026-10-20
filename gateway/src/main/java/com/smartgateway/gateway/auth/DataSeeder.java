package com.smartgateway.gateway.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/** Creates the demo user and the admin user on first start. */
@Component
public class DataSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DataSeeder.class);
    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final String demoPassword;
    private final String adminPassword;

    public DataSeeder(UserRepository users, PasswordEncoder encoder,
                      @Value("${smartgateway.seed.demo-password:password123}") String demoPassword,
                      @Value("${smartgateway.seed.admin-password:admin123}") String adminPassword) {
        this.users = users;
        this.encoder = encoder;
        this.demoPassword = demoPassword;
        this.adminPassword = adminPassword;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (users.find("demo").isEmpty() && users.create("demo", encoder.encode(demoPassword), "USER")) {
            log.info("Created demo user 'demo'");
        }
        if (users.find("admin").isEmpty() && users.create("admin", encoder.encode(adminPassword), "ADMIN")) {
            log.info("Created admin user 'admin'");
        }
    }
}
