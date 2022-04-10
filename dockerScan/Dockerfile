FROM python:2.7.18-stretch

RUN apt update && apt install -y --no-install-recommends \
    curl ca-certificates\
    python2.7 \
    python2.7-dev \
    gcc \
    g++ \
    g++-multilib \
    cmake libc6-dev libc6-dev-i386 libclang-dev llvm-dev automake \
    git

RUN pip install cxxfilt==0.2.2 \
    && pip install PyBindGen==0.20.1 \
    && pip install pygccxml

RUN git clone https://github.com/CastXML/CastXML.git \
    && cd CastXML \
    && git reset v0.2.0 \
    && cd .. \
    && mkdir castxml_build && cd castxml_build \
    && cmake ../CastXML \
    && make && make install

WORKDIR /ns3/

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT [ "/entrypoint.sh" ]
