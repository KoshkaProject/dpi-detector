FROM python:3.14-alpine

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dpi_detector.py .
COPY domains.txt .
COPY tcp_16_20_targets.json .
COPY config.py .

CMD ["python", "dpi_detector.py"]