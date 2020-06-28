from java:8
expose 9191
add target/auth-server-0.0.1-SNAPSHOT.jar /opt/auth-server-0.0.1-SNAPSHOT.jar
workdir /opt
entrypoint ["java","-jar","auth-server-0.0.1-SNAPSHOT.jar"]