FROM rust:1.67 as builder
WORKDIR /usr/src/portfolio-backend
COPY . .
RUN cargo install --path .

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/portfolio-backend /usr/local/bin/portfolio-backend
CMD ["portfolio-backend"]