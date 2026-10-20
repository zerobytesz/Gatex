# Multi-stage build used for every module:  docker build --build-arg MODULE=gateway -t smart-gateway .
FROM maven:3.9.9-eclipse-temurin-17 AS build
ARG MODULE
WORKDIR /src
COPY pom.xml .
COPY gateway/pom.xml gateway/
COPY user-service/pom.xml user-service/
COPY order-service/pom.xml order-service/
RUN mvn -q -B -pl ${MODULE} -am dependency:go-offline || true
COPY gateway/src gateway/src
COPY user-service/src user-service/src
COPY order-service/src order-service/src
RUN mvn -q -B -pl ${MODULE} -am package -DskipTests

FROM eclipse-temurin:17-jre
ARG MODULE
WORKDIR /app
COPY --from=build /src/${MODULE}/target/${MODULE}.jar /app/app.jar
RUN useradd --system --uid 10001 appuser
USER appuser
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]
