FROM ubuntu:20.04

# Install git, zip, python-pip, cmake, g++, zlib, libssl, libcurl, java, maven via apt
# Specify DEBIAN_FRONTEND and TZ to prevent tzdata hanging
RUN apt-get update && \
    apt-get upgrade -y && \
    DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"  apt-get install -y git zip wget python3 python3-pip cmake g++ zlib1g-dev libssl-dev libcurl4-openssl-dev openjdk-8-jdk doxygen ninja-build

RUN apt install -y vim
#RUN git clone --recurse-submodules --branch 1.9.40 https://github.com/aws/aws-sdk-cpp
RUN git clone --recurse-submodules https://github.com/aws/aws-sdk-cpp
#RUN git clone --recurse-submodules --branch version1.9 https://github.com/aws/aws-sdk-cpp
RUN mkdir sdk_build
RUN cd sdk_build
RUN cmake ../aws-sdk-cpp -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3"
RUN make
RUN make install
RUN rm -rf ./aws-sdk-cpp

WORKDIR /usr/src/myapp
COPY ./seal_installer.sh /usr/src/myapp
RUN ./seal_installer.sh
RUN apt-get -y install libcpprest-dev

#RUN mkdir /root/.aws
#COPY credentials /root/.aws
COPY . /usr/src/myapp
WORKDIR /usr/src/myapp
RUN mkdir Release
WORKDIR Release
#RUN cp ../seal-params* ../pk-fhe* ../sk-fhe* .
RUN cmake -DCMAKE_BUILD_TYPE=Release ..
RUN mkdir /tmp/out
#RUN make End_2_End
RUN make Auxiliary_Server
RUN make Data_Owner
RUN make Destination_Server


