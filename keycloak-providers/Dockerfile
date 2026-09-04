FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN mvn -q -DskipTests package

FROM quay.io/keycloak/keycloak:26.7
COPY --from=build /src/target/keycloak-vault-jwt-compat.jar /opt/keycloak/providers/keycloak-vault-jwt-compat.jar
