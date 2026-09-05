FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# 1. Install necessary system tools as ROOT
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 2. Install kubectl
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 3. Create directories and ensure permissions
RUN mkdir -p /evidence /home/agent/ric_forensics \
    && groupadd --gid 10001 ztx \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin ztx \
    && chown -R 10001:10001 /app /evidence /home/agent/ric_forensics

COPY --chown=10001:10001 . /app/

# 4. CRITICAL: We need root-like access to talk to the K8s API/Host, 
# but if you must use the user ztx, ensure you have volume mounts 
# in your deployment YAML for .kube/config.
# For now, we keep USER 10001 for security.
USER 10001:10001

EXPOSE 5000

CMD ["python3", "/app/app.py"]
