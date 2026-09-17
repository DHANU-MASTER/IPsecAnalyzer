FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /app
COPY pom.xml .
COPY src src
RUN mvn clean package -DskipTests -B

# Runtime stage using active Eclipse Temurin JRE image
FROM eclipse-temurin:17-jre

# libpcap is required by pcap4j at runtime (native library for pcap parsing)
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Ensure runtime directories exist
RUN mkdir -p /app/models /app/dataset /app/uploads /tmp/ipsec_uploads

# Copy compiled JAR from builder
COPY --from=builder /app/target/ipsec-analyzer-1.0.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
