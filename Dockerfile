FROM ruby:latest
RUN gem install winrm winrm-fs colorize stringio
RUN git clone https://github.com/Hackplayers/evil-winrm.git
VOLUME ["/data"]
WORKDIR /data
ENTRYPOINT ["/evil-winrm/evil-winrm.rb"]
