FROM debian:buster

RUN apt update && apt upgrade -y

RUN mkdir /infection/