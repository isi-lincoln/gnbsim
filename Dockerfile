# Copyright 2021-present Open Networking Foundation
# Copyright 2024-present Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

FROM golang:1.22.3-bookworm

LABEL maintainer="Aether SD-Core <dev@aetherproject.org>"

RUN apt-get update && \
    apt-get -y install --no-install-recommends \
    vim \
    ethtool \
    iproute2 \
    net-tools \
    netcat-traditional \
    ffmpeg \
    tcpdump \
    iputils-ping \
    libpcap-dev && \
    apt-get clean

WORKDIR $GOPATH/src/gnbsim
COPY . .
RUN make all

CMD "/bin/sleep 100d"
