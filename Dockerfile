FROM --platform=$BUILDPLATFORM eclipse-temurin:25-jdk AS builder
WORKDIR /build
COPY gradle ./gradle
COPY gradlew settings.gradle.kts build.gradle.kts ./
RUN chmod +x gradlew && ./gradlew --no-daemon --quiet dependencies
COPY src ./src
RUN ./gradlew --no-daemon --quiet installDist -x test

FROM eclipse-temurin:25-jre-alpine
RUN adduser -D -u 10001 auka && mkdir /data && chown auka /data
COPY --from=builder /build/build/install/auka-backend/lib /app/lib
COPY deploy/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
USER auka
ENV DATA_DIR=/data PORT=8443
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["/app/entrypoint.sh"]
