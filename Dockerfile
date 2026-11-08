FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY dfsha ./dfsha
COPY tests ./tests
ENV PYTHONPATH=/app PYTHONUNBUFFERED=1
RUN printf '#!/bin/sh\nexec python -m dfsha.client.cli "$@"\n' > /usr/local/bin/dfsha && chmod +x /usr/local/bin/dfsha
