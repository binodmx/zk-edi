# Use the official minimal Python Alpine image
FROM python:3.10-alpine

# Ensure Python output is sent straight to terminal (unbuffered)
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install build dependencies required for compiling blspy
RUN apk add --no-cache --virtual .build-deps cmake build-base git

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "app.py"]
