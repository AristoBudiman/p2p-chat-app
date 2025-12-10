FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501
EXPOSE 5000-5010

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]