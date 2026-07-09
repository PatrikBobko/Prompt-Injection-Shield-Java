# syntax=docker/dockerfile:1.7

# Build the executable Spring Boot jar in an isolated, reproducible Maven stage.
FROM maven:3.9.9-eclipse-temurin-21 AS build

WORKDIR /workspace

# Copy the build descriptor first so dependency downloads are cached independently
# from application-source changes.
COPY pom.xml ./
RUN --mount=type=cache,target=/root/.m2 \
    mvn --batch-mode --no-transfer-progress dependency:go-offline

COPY src ./src
RUN --mount=type=cache,target=/root/.m2 \
    mvn --batch-mode --no-transfer-progress package -DskipTests

# Keep build tooling out of the runtime image. curl is intentionally retained only
# for the container health check; the process itself runs as an unprivileged user.
FROM eclipse-temurin:21-jre-jammy AS runtime

LABEL org.opencontainers.image.title="Prompt Injection Shield Service" \
      org.opencontainers.image.description="Spring Boot service for detecting hidden prompt-injection payloads"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends curl \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build --chown=app:app /workspace/target/*.jar /app/app.jar

USER app:app

EXPOSE 8080

ENV JAVA_TOOL_OPTIONS="-XX:InitialRAMPercentage=25.0 -XX:MaxRAMPercentage=75.0 -XX:+ExitOnOutOfMemoryError -Djava.awt.headless=true"

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl --fail --silent --show-error --max-time 3 http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
