FROM ubuntu:16.04 as build

MAINTAINER Tom Llewellyn-smith <tom@stellar.org>

RUN apt-get update && apt-get install -qy curl \
        build-essential \
        libpq-dev \
        libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

ENV PATH "/root/.cargo/bin:$PATH"

ADD . /var/lib/slingshot/

WORKDIR /var/lib/slingshot/demo

# accept defaults
RUN curl https://sh.rustup.rs -sSf > rustup-init.sh && \
    bash rustup-init.sh -y && \
    rustup install $(cat rust-toolchain) && \
    cargo install diesel_cli --no-default-features --features sqlite && \
    cargo build && \
    diesel database reset && \
    mkdir bin/ && \
    mv target/debug/zkvm-demo bin/ && \
    cargo clean

FROM ubuntu:16.04

EXPOSE 8000

ENV ROCKET_PORT=8000 \
    ROCKET_ADDRESS=0.0.0.0

RUN apt-get update && apt-get install -qy libpq-dev \
        libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /var/lib/slingshot/demo/migrations/ /app/migrations/
COPY --from=build /var/lib/slingshot/demo/static/ /app/static/
COPY --from=build /var/lib/slingshot/demo/templates/ /app/templates/
COPY --from=build /var/lib/slingshot/demo/Rocket.toml /app/
COPY --from=build /var/lib/slingshot/demo/diesel.toml /app/
COPY --from=build /var/lib/slingshot/demo/.env /app/
COPY --from=build /var/lib/slingshot/demo/demodb.sqlite /app/
COPY --from=build /var/lib/slingshot/demo/bin/zkvm-demo /app/

WORKDIR /app/

ENTRYPOINT ["/app/zkvm-demo"]
