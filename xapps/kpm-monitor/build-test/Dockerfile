FROM 127.0.0.1:80/hw-python:latest

RUN python3 -m pip install --no-cache-dir asn1tools

CMD ["python3", "-c", "import asn1tools; from ricxappframe.rmr import rmr; print('OK asn1tools and RMR ready')"]
