FROM ubuntu:latest

WORKDIR /usr/src/app

COPY app.py /usr/src/app
RUN apt-get update \
    && apt-get --yes install python3.10 python3-pip python3-dev libpcap0.8 nmap \
    && pip3 install --no-cache-dir --break-system-packages scapy python-nmap

CMD [ "/usr/bin/python3", "-u", "/usr/src/app/app.py" ]
