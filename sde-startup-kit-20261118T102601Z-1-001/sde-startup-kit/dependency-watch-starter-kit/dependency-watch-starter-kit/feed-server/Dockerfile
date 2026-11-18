FROM python:3.12-slim
WORKDIR /app
COPY app.py .
COPY feeds ./feeds
ENV PYTHONUNBUFFERED=1
CMD ["python", "app.py"]
