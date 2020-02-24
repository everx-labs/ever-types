ARG TON_LABS_TYPES_IMAGE=tonlabs/ton-labs-types:latest

FROM alpine:latest as ton-labs-types-src
RUN addgroup --gid 1000 jenkins && \
    adduser -D -G jenkins jenkins
COPY --chown=jenkins:jenkins ./Cargo.* ./*.md ./*.rs /tonlabs/ton-labs-types/
COPY --chown=jenkins:jenkins ./src /tonlabs/ton-labs-types/src
VOLUME ["/tonlabs/ton-labs-types"]
USER jenkins

FROM $TON_LABS_TYPES_IMAGE as ton-labs-types-source
FROM rust:latest as ton-labs-types-rust
RUN apt -qqy update && apt -qyy install apt-utils && \
    curl -sL https://deb.nodesource.com/setup_12.x | bash - && \
    apt-get install -qqy nodejs && \
    adduser --group jenkins && \
    adduser -q --disabled-password --gid 1000 jenkins && \
    mkdir /tonlabs && chown -R jenkins:jenkins /tonlabs
COPY --from=ton-labs-types-source --chown=jenkins:jenkins /tonlabs/ton-labs-types /tonlabs/ton-labs-types
