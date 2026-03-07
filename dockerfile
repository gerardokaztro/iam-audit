FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
COPY src/ .

RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "iam_audit.py"]

EXPOSE 8000