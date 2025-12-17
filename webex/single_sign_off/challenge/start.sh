#!/bin/bash

(cd /app/document-portal && python3 app.py) &

(cd /app/nite-vault && gunicorn --bind unix:/tmp/nite-vault.sock app:app) &

cd /app/nite-sso
gunicorn --bind 0.0.0.0:8989 run:app
