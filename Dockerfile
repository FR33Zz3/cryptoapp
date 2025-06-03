FROM eclipse-temurin:17-jdk-jammy
WORKDIR /app
COPY target/cryptoapp-1.0-SNAPSHOT.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
