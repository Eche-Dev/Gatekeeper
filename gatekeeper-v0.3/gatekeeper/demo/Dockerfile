FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 8000
# Un solo worker: con el backend en memoria el contador es por proceso, y la
# demo quiere que el rate limit se vea como lo documenta el README.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
