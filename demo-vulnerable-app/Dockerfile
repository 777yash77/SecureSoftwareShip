# Vulnerability: Unpinned base image tag (:latest)
FROM python:latest

WORKDIR /app

# Vulnerability: Sensitive API key hardcoded in Docker ENV
ENV API_SECRET_TOKEN="sk_live_999988887777666655554444"

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Vulnerability: Missing USER directive (Container executes as root)
EXPOSE 5000
CMD ["python", "app.py"]
