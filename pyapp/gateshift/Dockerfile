# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

CMD ["python", "-u", "main.py"]