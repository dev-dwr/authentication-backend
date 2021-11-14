FROM openjdk:11
ARG JAR_FILE=build/libs/authentication-backend-0.0.1-SNAPSHOT.jar
COPY ${JAR_FILE} app.jar
COPY wait-for-it.sh wait-for-it.sh
ENTRYPOINT ["./wait-for-it.sh", "mysqldb:3306", "--", "java", "-jar", "app.jar"]
