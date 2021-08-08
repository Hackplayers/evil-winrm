# Evil-WinRM Dockerfile

# Base image
FROM ruby:latest

# Credits & Data
LABEL \
    name="Evil-WinRM" \
    author="CyberVaca <cybervaca@gmail.com>" \
    maintainer="OscarAkaElvis <oscar.alfonso.diaz@gmail.com>" \
    description="The ultimate WinRM shell for hacking/pentesting"

#Env vars
ENV EVILWINRM_URL="https://github.com/Hackplayers/evil-winrm.git"

# Install dependencies
RUN gem install \
    winrm \
    winrm-fs \
    stringio \
    logger \
    fileutils

# Create volume for powershell scripts
RUN mkdir /ps1_scripts
VOLUME /ps1_scripts

# Create volume for executable files
RUN mkdir /exe_files
VOLUME /exe_files

# Create volume for data (upload/download)
RUN mkdir /data
VOLUME /data

# Set workdir
WORKDIR /opt/

#Evil-WinRM install method 1 (only one method can be used, other must be commented)
#Install Evil-WinRM (Docker Hub automated build process)
RUN mkdir evil-winrm
COPY . /opt/evil-winrm

#Evil-WinRM install method 2 (only one method can be used, other must be commented)
#Install Evil-WinRM (manual image build)
#Uncomment git clone line and one of the ENV vars to select branch (master->latest, dev->beta)
#ENV BRANCH="master"
#ENV BRANCH="dev"
#RUN git clone -b ${BRANCH} ${EVILWINRM_URL}

# Make script file executable
RUN chmod +x evil-winrm/*.rb

# Clean and remove useless files
RUN rm -rf /opt/evil-winrm/resources > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/.github > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/CONTRIBUTING.md > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/CODE_OF_CONDUCT.md > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/Dockerfile > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/Gemfile* > /dev/null 2>&1 && \
    rm -rf /tmp/* > /dev/null 2>&1

# Start command (launching Evil-WinRM)
ENTRYPOINT ["/opt/evil-winrm/evil-winrm.rb"]
