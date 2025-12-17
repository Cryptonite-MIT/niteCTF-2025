FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir torch numpy rich


COPY oracle.py .
COPY model.py .
COPY loss.py .
COPY weights.pt .


EXPOSE 5000


CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:python oracle.py"]
