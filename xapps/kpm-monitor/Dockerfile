FROM 127.0.0.1:80/hw-python:latest

WORKDIR /app

RUN python3 -m pip install --no-cache-dir asn1tools && \
    addgroup -g 10001 xappuser 2>/dev/null || true && \
    adduser -D -u 10001 -G xappuser xappuser 2>/dev/null || true

COPY app.py /app/app.py
COPY lib /app/lib

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64

RUN chown -R 10001:10001 /app

USER 10001:10001

EXPOSE 8092
EXPOSE 4562

CMD ["python3", "/app/app.py"]
