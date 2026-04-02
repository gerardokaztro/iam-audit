FROM python:3.14-slim-bookworm@sha256:55e465cb7e50cd1d7217fcb5386aa87d0356ca2cd790872142ef68d9ef6812b4

WORKDIR /app

COPY requirements.txt .
COPY src/ .

RUN pip install --upgrade pip==26.0 && \ 
    pip install -r requirements.txt

ENTRYPOINT ["python3", "iam_audit.py"]

EXPOSE 8000