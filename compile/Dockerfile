FROM ubuntu:focal

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y \
    python3.8 \
    python3.8-dev \
    python3-pip \
    gcc \
    g++ \
    git \
    curl \
    wget

RUN git clone https://github.com/gjcarneiro/pybindgen /pybindgen/ \
    && cd /pybindgen/ \
    && git reset --hard 823d8b2b

RUN apt install -y castxml \
    && pip3 install cxxfilt \
    && pip3 install pygccxml==1.9.0

WORKDIR /ns3/

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT [ "/entrypoint.sh" ]
