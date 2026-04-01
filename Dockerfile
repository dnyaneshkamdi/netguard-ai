# Base image
FROM python:3.11-slim

# Working directory
WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Requirements copy karo
COPY requirements.txt .

# Packages install karo
RUN pip install --no-cache-dir -r requirements.txt

# Poora project copy karo
COPY . .

# Port expose karo
EXPOSE 5000

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production

# Run karo
CMD ["python", "-m", "web.app"]
