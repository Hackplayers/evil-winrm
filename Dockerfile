# Evil-WinRM Dockerfile

# Base image
FROM ruby:4.0.1-alpine3.23 AS final
FROM ruby:4.0.1-alpine3.23 AS build

# Credits & Data
LABEL \
    name="Evil-WinRM" \
    author="CyberVaca <cybervaca@gmail.com>" \
    maintainer="OscarAkaElvis <oscar.alfonso.diaz@gmail.com>" \
    description="The ultimate WinRM shell for hacking/pentesting"

#Env vars
ENV EVILWINRM_URL="https://github.com/Hackplayers/evil-winrm.git"

# Install git and bash for regular usefor Evil-WinRM install method 2
RUN apk --no-cache add git bash

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

# Clean and remove useless files
RUN rm -rf /opt/evil-winrm/resources > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/.github > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/CONTRIBUTING.md > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/CODE_OF_CONDUCT.md > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/Dockerfile > /dev/null 2>&1 && \
    #rm -rf /opt/evil-winrm/Gemfile* > /dev/null 2>&1 && \
    #rm -rf /opt/evil-winrm/evil-winrm.gemspec > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/.rubocop.yml > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/.editorconfig > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/.gitignore > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/.gitattributes > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/bin > /dev/null 2>&1

# Rename script name
RUN mv /opt/evil-winrm/evil-winrm.rb /opt/evil-winrm/evil-winrm && \
    chmod +x /opt/evil-winrm/evil-winrm

# Base final image
FROM final

# Install dependencies
RUN apk --no-cache add \
    yaml \
    krb5-libs \
    libffi

# Install build dependencies to be able to build native extensions when install ruby dependencies
RUN apk add --no-cache --virtual build-dependencies build-base

# Make the Evil-WinRM paths available
ENV PATH=$PATH:/opt/evil-winrm

# Copy built stuff from build image
COPY --from=build /opt /opt

# Set directory for the dependencies installation
WORKDIR /opt/evil-winrm

# Install Evil-WinRM ruby dependencies
RUN bundle config set path.system true && bundle install

# Remove build dependencies
RUN apk del build-dependencies

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
