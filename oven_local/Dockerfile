ARG BUILD_FROM
FROM $BUILD_FROM

# scapy needs raw sockets; iptables for the REDIRECT; conntrack to flush the old flow;
# openssl to generate the impersonation certs; tcpdump pulled in for scapy's convenience.
RUN apk add --no-cache \
      python3 py3-pip \
      iptables ip6tables iptables-legacy \
      conntrack-tools \
      tcpdump \
      openssl \
 && pip3 install --no-cache-dir --break-system-packages \
      scapy paho-mqtt

COPY run.sh /run.sh
COPY oven_bridge.py /oven_bridge.py
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
