FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY collector.py .
EXPOSE 2055/udp
CMD ["python", "collector.py"]
