FROM debian:buster

RUN apt update && \
    apt upgrade -y \
    apt install -y python3 python3-pip

RUN pip3 install pycryptodome

COPY fileGenerator.sh ./
COPY extensions ./
COPY stockholm.py ./

RUN chmod +x /usr/local/bin/fileGenerator.sh

CMD ["fileGenerator.sh"]
