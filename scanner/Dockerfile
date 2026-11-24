# Supply an explicitly reviewed Python image digest; there is no floating default.
ARG PYTHON_BASE
FROM ${PYTHON_BASE}
WORKDIR /app
COPY backend/app/services/header_analyzer.py /app/header_analyzer.py
COPY scanner/container_entry.py /app/container_entry.py
USER 65532:65532
ENTRYPOINT ["python", "-I", "-S", "-B", "/app/container_entry.py"]
