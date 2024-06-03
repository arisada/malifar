from ubuntu:22.04
RUN apt update && \
    apt upgrade -y
RUN apt install -y cmake python3-dev python3-pip
RUN apt install -y libssl-dev swig
RUN apt install -y netcat-openbsd bind9-dnsutils
COPY requirements.txt /
RUN pip3 install -r /requirements.txt
RUN useradd -m malifar
USER malifar
WORKDIR /malifar/

CMD ["/malifar/dumper.py"]

