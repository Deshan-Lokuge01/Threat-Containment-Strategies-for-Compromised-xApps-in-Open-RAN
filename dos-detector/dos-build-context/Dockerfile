# --- Stage 1: Builder ---
FROM python:3.8-slim as builder
RUN apt-get clean -y && apt-get update -y && apt-get install -y wget curl git gcc

ARG RMR_VERSION=4.9.4
ARG RMR_LIB_URL=https://packagecloud.io/o-ran-sc/release/packages/debian/stretch/rmr_${RMR_VERSION}_amd64.deb/download.deb
RUN wget --content-disposition ${RMR_LIB_URL} && dpkg -i rmr_${RMR_VERSION}_amd64.deb

ARG E2AP_VERSION=1.1.0
ARG E2AP_LIB_URL=https://packagecloud.io/o-ran-sc/release/packages/debian/stretch/riclibe2ap_${E2AP_VERSION}_amd64.deb/download.deb
RUN wget --content-disposition ${E2AP_LIB_URL} && dpkg -i riclibe2ap_${E2AP_VERSION}_amd64.deb

# --- Stage 2: Final Image ---
FROM python:3.8-slim

RUN apt-get update && apt-get install -y iputils-ping net-tools curl && apt-get clean

COPY --from=builder /usr/local/lib/librmr_si.so.4.9.4 /usr/local/lib/librmr_si.so
COPY --from=builder /usr/local/lib/libriclibe2ap.so.1.1.0 /usr/local/lib/libriclibe2ap.so
ENV LD_LIBRARY_PATH=/usr/local/lib

# Install Python Dependencies
RUN pip install --no-cache-dir \
    protobuf kubernetes msgpack \
    google-api-python-client grpcio \
    inotify_simple mdclogpy ricsdl \
    ricxappframe asn1tools

WORKDIR /app

# Copy the core xApp scripts and routing table
COPY lib ./lib
COPY dos_detector_xapp.py ./app.py
COPY correct_rtg.rt ./correct_rtg.rt

# Explicitly tell the RMR library where the routing table is
ENV RMR_SEED_RT=/app/correct_rtg.rt

# Ensure the script is executable
RUN chmod +x ./app.py

ENTRYPOINT ["python3", "app.py"]
