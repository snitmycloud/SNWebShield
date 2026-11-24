ARG PYTHON_BASE
FROM ${PYTHON_BASE}
RUN apt-get update && apt-get install -y --no-install-recommends nmap iptables \
    && dpkg-query -W nmap iptables > /usr/local/share/snwebshield-package-versions \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY backend/app/services/nmap_policy.py /app/nmap_policy.py
COPY scanner/nmap/entry.py /app/nmap_entry.py
COPY scanner/nmap/guard.py /app/nmap_guard.py
USER 65532:65532
ENTRYPOINT ["python", "-I", "-S", "-B", "/app/nmap_entry.py"]
