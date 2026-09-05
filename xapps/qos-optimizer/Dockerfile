FROM python:3.11-slim
WORKDIR /app
RUN useradd -u 10001 -m xappuser
COPY common/ztx_common /app/ztx_common
COPY qos-optimizer/app.py /app/app.py
RUN chmod +x /app/app.py
USER xappuser
EXPOSE 8080
CMD ["python3", "/app/app.py"]
