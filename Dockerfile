FROM openjdk:8
COPY target/basicAuth-1.0-SNAPSHOT.jar basicAuth-1.0-SNAPSHOT.jar 
EXPOSE 8080 
CMD [ "java", "-jar", "basicAuth-1.0-SNAPSHOT.jar" ]