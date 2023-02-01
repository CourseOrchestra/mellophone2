FROM eclipse-temurin:17-jdk-alpine
VOLUME /config
COPY target/*.jar /mellophone2.jar
COPY docker-example-config config
ENTRYPOINT ["java","-jar","/mellophone2.jar", "-Dspring.config.location=/config"]
