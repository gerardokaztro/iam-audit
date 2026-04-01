FROM python:3.13-slim-bookworm@sha256:cb4d57d6b3bba54e4584ac09c136758e0cbf0cced945bcb2f1e160d7c38af2eb

WORKDIR /app

COPY requirements.txt .
COPY src/ .

RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "iam_audit.py"]

EXPOSE 8000