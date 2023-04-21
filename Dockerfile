# Evil-WinRM Dockerfile

# Base image
FROM alpine:3.14 AS final
FROM alpine:3.14 AS build

# Credits & Data
LABEL \
    name="Evil-WinRM" \
    author="CyberVaca <cybervaca@gmail.com>" \
    maintainer="OscarAkaElvis <oscar.alfonso.diaz@gmail.com>" \
    description="The ultimate WinRM shell for hacking/pentesting"

#Env vars
ENV EVILWINRM_URL="https://github.com/Hackplayers/evil-winrm.git"

# Install dependencies for building ruby with readline and openssl support
RUN apk --no-cache add cmake \
    clang \
    clang-dev \
    make \
    gcc \
    g++ \
    libc-dev \
    linux-headers \
    readline \
    readline-dev \
    yaml \
    yaml-dev \
    libffi \
    libffi-dev \
    zlib \
    zlib-dev \
    openssl-dev \
    openssl \
    bash

# Make the ruby path available
ENV PATH=$PATH:/opt/rubies/ruby-3.2.2/bin

# Get ruby-install for building ruby 3.2.2
RUN cd /tmp/ && \
    wget -O /tmp/ruby-install-0.8.1.tar.gz https://github.com/postmodern/ruby-install/archive/v0.8.1.tar.gz && \
    tar -xzvf ruby-install-0.8.1.tar.gz && \
    cd ruby-install-0.8.1/ && make install && \
    ruby-install -c ruby 3.2.2 -- --with-readline-dir=/usr/include/readline --with-openssl-dir=/usr/include/openssl --disable-install-rdoc

# Evil-WinRM install method 1 (only one method can be used, other must be commented)
# Install Evil-WinRM (DockerHub automated build process)
RUN mkdir /opt/evil-winrm
COPY . /opt/evil-winrm

# Evil-WinRM install method 2 (only one method can be used, other must be commented)
# Install Evil-WinRM (manual image build)
# Uncomment git clone line and one of the ENV vars to select branch (master->latest, dev->beta)
#ENV BRANCH="master"
#ENV BRANCH="dev"
#RUN git clone -b ${BRANCH} ${EVILWINRM_URL}

# Install Evil-WinRM ruby dependencies
RUN gem install winrm \
    winrm-fs \
    stringio \
    logger \
    fileutils

# Clean and remove useless files
RUN rm -rf /opt/evil-winrm/resources > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/.github > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/CONTRIBUTING.md > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/CODE_OF_CONDUCT.md > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/Dockerfile > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/Gemfile* > /dev/null 2>&1

# Rename script name
RUN mv /opt/evil-winrm/evil-winrm.rb /opt/evil-winrm/evil-winrm && \
    chmod +x /opt/evil-winrm/evil-winrm

# Base final image
FROM final

# Install readline and other dependencies
RUN apk --no-cache add \
    readline \
    yaml \
    libffi \
    zlib \
    openssl

# Make the ruby and Evil-WinRM paths available
ENV PATH=$PATH:/opt/rubies/ruby-3.2.2/bin:/opt/evil-winrm

# Copy built stuff from build image
COPY --from=build /opt /opt

# Create volume for powershell scripts
RUN mkdir /ps1_scripts
VOLUME /ps1_scripts

# Create volume for executable files
RUN mkdir /exe_files
VOLUME /exe_files

# Create volume for data (upload/download)
RUN mkdir /data
VOLUME /data

# set current working dir
WORKDIR /data

# Start command (launching Evil-WinRM)
ENTRYPOINT ["evil-winrm"]
