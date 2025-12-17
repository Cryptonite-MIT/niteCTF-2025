FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -M -s /usr/sbin/nologin user && \
    chown -R user:user /app

USER user

EXPOSE 5000

CMD ["gunicorn", "-w" , "1" , "-b", "0.0.0.0:5000", "app:app"]