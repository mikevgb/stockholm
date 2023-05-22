FROM debian:buster

RUN apt update && \
    apt upgrade -y && \
    apt install -y python3 python3-pip

RUN pip3 install pycryptodome

COPY fileGenerator.sh extensions stockholm.py ./

RUN bash ./fileGenerator.sh

ENTRYPOINT ["tail", "-f", "/dev/null"]