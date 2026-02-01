FROM rust:alpine AS build
RUN apk upgrade --no-cache && apk --no-cache add musl-dev
WORKDIR /srv
COPY Cargo.toml .
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
  cargo fetch
COPY . .
RUN cargo build --release

FROM alpine AS runtime
COPY --from=build /srv/target/release/secoder /bin
USER root
EXPOSE 80
CMD ["secoder", "-c", "/etc/config.json"]
