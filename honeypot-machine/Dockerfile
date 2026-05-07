FROM python:3.12-slim

WORKDIR /app

# system deps (adjust if needed)
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# install python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy app
COPY . .

CMD ["python", "main.py"]