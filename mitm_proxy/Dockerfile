FROM python:3.11-slim

# Install SCTP support
RUN apt-get update && \
    apt-get install -y libsctp-dev lksctp-tools && \
    pip install pysctp

# Copy your MITM proxy script
COPY sctp_mitm_proxy.py /app/
WORKDIR /app

EXPOSE 38412/sctp
# Control port
EXPOSE 1337/tcp  

CMD ["python3", "sctp_mitm_proxy.py"]