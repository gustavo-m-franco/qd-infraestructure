# Start from a base image, e.g., Ubuntu
FROM ubuntu:20.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install basic tools
RUN apt-get update && apt-get install -y \
    curl \
    git \
    sudo \
    zip \
    unzip \
    software-properties-common  \
    build-essential

# Install Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - \
    && apt-get install -y nodejs

# Install Yarn
RUN npm install --global yarn

# Ruby and Fastlane (example versions, adjust as needed)
RUN apt-add-repository ppa:brightbox/ruby-ng \
    && apt-get update && apt-get install -y ruby2.7 ruby2.7-dev \
    && gem install fastlane -NV

# Install CocoaPods dependencies
RUN apt-get install -y libffi-dev

# Set the working directory
WORKDIR /usr/src/app

# Copy your project files into the Docker image
COPY . .

# Command to run on container start
CMD [ "/bin/bash" ]
