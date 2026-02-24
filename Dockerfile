FROM python:3.13-slim

COPY requirements.txt requirements.txt
RUN pip install --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONUNBUFFERED=1

ENV HOME=/app
WORKDIR /app

COPY . . 

EXPOSE 8080
CMD ["streamlit", "run", "app.py", "--server.port=8080", "--server.address=0.0.0.0"]

