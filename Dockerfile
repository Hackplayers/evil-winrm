# Evil-WinRM Dockerfile

# Base image
FROM alpine:3.23.3 AS final
FROM alpine:3.23.3 AS build

# Credits & Data
LABEL \
    name="Evil-WinRM" \
    author="CyberVaca <cybervaca@gmail.com>" \
    maintainer="OscarAkaElvis <oscar.alfonso.diaz@gmail.com>" \
    description="The ultimate WinRM shell for hacking/pentesting"

#Env vars
ENV EVILWINRM_URL="https://github.com/Hackplayers/evil-winrm.git"

# Install dependencies for building Ruby and native gems
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
    bash \
    git

# Make the ruby path available
ENV PATH=$PATH:/opt/rubies/ruby-4.0.1/bin

# Get ruby-install for building ruby 4.0.1
RUN cd /tmp/ && \
    wget -O /tmp/ruby-install-0.10.2.tar.gz https://github.com/postmodern/ruby-install/archive/v0.10.2.tar.gz && \
    tar -xzvf ruby-install-0.10.2.tar.gz && \
    cd ruby-install-0.10.2/ && make install && \
    ruby-install -c ruby 4.0.1 -- --disable-install-rdoc

# Set directory for the deploy of the application
WORKDIR /opt

# Evil-WinRM install method 1 (only one method can be used, other must be commented)
# Install Evil-WinRM (DockerHub automated build process)
RUN mkdir evil-winrm
COPY . /opt/evil-winrm

# Evil-WinRM install method 2 (only one method can be used, other must be commented)
# Install Evil-WinRM (manual image build)
# Uncomment git clone line and the ENV var to select ai branch
#ENV BRANCH="ai"
#RUN git clone -b ${BRANCH} ${EVILWINRM_URL}

# Install Evil-WinRM ruby dependencies including AI ruby gems
RUN gem update && gem install --no-document anthropic \
    benchmark \
    csv \
    fileutils \
    langchainrb \
    logger \
    mistral-ai \
    ollama-ai \
    readline \
    readline-ext \
    ruby-openai \
    stringio \
    syslog \
    winrm \
    winrm-fs

# Clean and remove useless files
RUN rm -rf /opt/evil-winrm/resources > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/.github > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/CONTRIBUTING.md > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/CODE_OF_CONDUCT.md > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/Dockerfile > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/Gemfile* > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/evil-winrm.gemspec > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/.rubocop.yml > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/.editorconfig > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/.gitignore > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/.gitattributes > /dev/null 2>&1 && \
    rm -rf /opt/evil-winrm/bin > /dev/null 2>&1

# Rename script name
RUN mv /opt/evil-winrm/evil-winrm-ai.rb /opt/evil-winrm/evil-winrm-ai && \
    chmod +x /opt/evil-winrm/evil-winrm-ai

# Base final image
FROM final

# Install readline and other dependencies
RUN apk --no-cache add \
    krb5-libs \
    libcurl \
    libffi \
    readline \
    yaml

# Make the ruby and Evil-WinRM paths available
ENV PATH=$PATH:/opt/rubies/ruby-4.0.1/bin:/opt/evil-winrm

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
ENTRYPOINT ["evil-winrm-ai"]
