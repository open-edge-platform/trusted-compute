FROM debian:bookworm

ENV NONINTERACTIVE=1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y cloud-init \
    git \
    whois \
    gettext-base \
    wget \
    curl \
    apt-transport-https \
    ca-certificates \
    gnupg \
    bc

RUN mkdir -p /etc/apt/keyrings
RUN curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
RUN echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list
RUN chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg
RUN apt-get update && apt-get install -y kubectl

RUN wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq
RUN chmod +x /usr/bin/yq
