FROM ubuntu:latest

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y \
    python \
    python-dev \
    gcc \
    g++ \
    git \
    curl

RUN git clone https://github.com/gjcarneiro/pybindgen /pybindgen/ \
    && cd /pybindgen/ \
    && git reset --hard 823d8b2b

RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py | python

RUN apt install -y castxml \
    && pip install cxxfilt \
    && pip install pygccxml==1.9.0

WORKDIR /ns3/

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT [ "/entrypoint.sh" ]
