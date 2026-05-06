FROM --platform=linux/arm64 frrouting/frr:latest

# Install SSH server and tools
RUN apk add --no-cache openssh-server openssh-client bash python3 tcpdump iproute2 \
    && ssh-keygen -A \
    && mkdir -p /root/.ssh /var/run/sshd

# Add lab SSH public key
COPY ssh-keys/lab_key.pub /root/.ssh/authorized_keys
RUN chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys

# Enable root SSH login (lab only)
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config \
    && echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config \
    && echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config \
    && echo "root:change-me-in-prod" | chpasswd

# CLI-over-HTTPS proxy (stdlib only — no pip required)
COPY cli_proxy.py /usr/local/bin/cli_proxy.py
RUN chmod +x /usr/local/bin/cli_proxy.py

# FRR daemons enabled at runtime via entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 8080
ENTRYPOINT ["/entrypoint.sh"]
