#!/bin/bash
# Enable required FRR daemons
sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons
sed -i 's/^ospfd=no/ospfd=yes/' /etc/frr/daemons
sed -i 's/^staticd=no/staticd=yes/' /etc/frr/daemons

# Copy device-specific FRR config if it exists
if [ -f /lab-config/frr.conf ]; then
    cp /lab-config/frr.conf /etc/frr/frr.conf
    chown frr:frr /etc/frr/frr.conf
fi

# Start SSH
/usr/sbin/sshd

# Start FRR
/usr/lib/frr/docker-start &

# Start CLI-over-HTTPS proxy on port 8080
python3 /usr/local/bin/cli_proxy.py &>/var/log/cli_proxy.log &

# Keep running
tail -f /dev/null
