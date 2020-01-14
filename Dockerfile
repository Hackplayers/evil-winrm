# Evil-WinRM Dockerfile

# Base image
FROM ruby:latest

# Credits & Data
LABEL \
    name="Evil-WinRM" \
    author="CyberVaca <cybervaca@gmail.com>" \
    maintainer="OscarAkaElvis <oscar.alfonso.diaz@gmail.com>" \
    description="The ultimate WinRM shell for hacking/pentesting"

# Install dependencies
RUN gem install \
    winrm \
    winrm-fs \
    stringio

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

# Install Evil-WinRM
RUN mkdir evil-winrm
COPY . /opt/evil-winrm

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
