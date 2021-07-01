# Creation of docker image which contains Ubuntu 16.04, Python 3.6 as default

FROM ubuntu:16.04
LABEL intTeam "haiharish13@gmail.com" "application base image"

# Install Python3 and change as default executable
RUN apt-get update && \
    apt-get install software-properties-common -y && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install python3.6 -y && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3.6 100 && \
    apt-get install -y python-pip python3-pip python3.6-dev build-essential
