#!/bin/bash
# Builds all modules and starts user-service (8081), order-service (8082) and the gateway (8080).
# Requirements: JDK 17+ and Maven 3.9+ (or open the project in IntelliJ IDEA, which bundles Maven).
set -e
cd "$(dirname "$0")"
command -v java >/dev/null || { echo "Java 17+ is required."; exit 1; }
command -v mvn  >/dev/null || { echo "Maven is required (https://maven.apache.org) - or run via IntelliJ / Docker."; exit 1; }
mkdir -p logs
echo "Building (first build downloads dependencies, this can take a few minutes)..."
mvn -q -B -DskipTests package
java -jar user-service/target/user-service.jar  > logs/user-service.log  2>&1 & echo $! > logs/user-service.pid
java -jar order-service/target/order-service.jar > logs/order-service.log 2>&1 & echo $! > logs/order-service.pid
sleep 3
echo ""
echo "Gateway:   http://localhost:8080"
echo "Dashboard: http://localhost:8080/dashboard.html   (admin / admin123)"
echo "Demo user: demo / password123"
echo "Press Ctrl+C to stop the gateway, then run ./stop-local.sh to stop the backends."
echo ""
exec java -jar gateway/target/gateway.jar
