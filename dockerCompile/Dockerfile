FROM python:3.8.12-slim

RUN apt update && apt install -y --no-install-recommends \
    gcc \
    g++ \
    && apt-get autoremove -y \
	&& apt-get clean -y \
	&& rm -rf /var/lib/apt/lists/*

RUN pip install PyBindGen==0.19.0

WORKDIR /ns3/

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT [ "/entrypoint.sh" ]
