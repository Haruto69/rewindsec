# RewindSec 2.0 synthetic ransomware technical-state target.
# Build from the repository root:
#   docker build --pull=false -t rewindsec2-ransomware-sandbox:2.0 \
#     -f docker/rewindsec2-target/Dockerfile .
FROM python:3.12-slim

WORKDIR /opt/rewindsec2
COPY docker/rewindsec2-target/runner.py /opt/rewindsec2/runner.py

RUN mkdir -p /workspace && chown 10001:10001 /workspace

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001

# A tiny idle process only. There is no listener, shell server, network service,
# scenario engine, autonomous impact logic, or ransomware implementation.
CMD ["python", "/opt/rewindsec2/runner.py", "idle"]
