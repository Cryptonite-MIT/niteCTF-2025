FROM python:3.11-slim

RUN useradd -m ctf

WORKDIR /app

RUN pip install --no-cache-dir Flask

COPY app.py .
COPY templates/ templates/

RUN sed -i 's/127.0.0.1/0.0.0.0/g' app.py

RUN chown -R ctf:ctf /app


USER ctf

EXPOSE 5000

CMD ["python3", "app.py"]


