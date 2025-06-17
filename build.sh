#!/usr/bin/env bash
# Установка OpenJDK 17
apt-get update
apt-get install -y openjdk-17-jdk

# Сборка проекта (если используете Maven)
mvn clean package

# Запуск приложения
java -jar target/cryptoapp-1.0-SNAPSHOT.jar --server.port=$PORT
