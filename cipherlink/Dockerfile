FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml .
COPY .mvn .mvn
COPY mvnw .
COPY src src
RUN mvn -B -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /workspace/target/cipherlink-0.0.1-SNAPSHOT.jar /app/cipherlink.jar
RUN mkdir -p /app/data && chown -R 10001:10001 /app
USER 10001:10001
ENV SERVER_PORT=8080 CIPHERLINK_DATA_DIR=/app/data
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "/app/cipherlink.jar"]
