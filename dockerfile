# Используем официальный образ OpenJDK 17 (Amazon Corretto или Eclipse Temurin)
FROM eclipse-temurin:17-jdk-jammy

# Рабочая директория внутри контейнера
WORKDIR /app

# Копируем JAR-файл в контейнер
COPY target/cryptoapp-1.0-SNAPSHOT.jar app.jar

# Открываем порт (указываем тот, который использует ваше приложение)
EXPOSE 8080

# Запускаем приложение
ENTRYPOINT ["java", "-jar", "app.jar"]