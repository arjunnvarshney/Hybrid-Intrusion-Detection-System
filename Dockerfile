# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
# libpcap is required for Scapy on Linux
# gcc and python3-dev are often needed for compiling some python packages like psutil or scikit-learn
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Ensure data and models directories exist
RUN mkdir -p data models

# Expose port 5000 for the Flask dashboard and WebSocket
EXPOSE 5000

# Run the IDS main script
# This script starts the sniffer, the detection orchestration, and the Flask dashboard
CMD ["python", "main.py"]
