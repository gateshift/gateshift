# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

FROM python:3.12-slim

WORKDIR /app

# Tailwind standalone CLI (single binary, no Node.js). Build-time only -
# runs once on container start, compiles templates → /app/static/app.css.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && case "$(uname -m)" in \
      x86_64)  TC_ARCH=linux-x64 ;; \
      aarch64) TC_ARCH=linux-arm64 ;; \
      *) echo "unsupported arch: $(uname -m)"; exit 1 ;; \
    esac \
 && curl -fsSL -o /usr/local/bin/tailwindcss \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-${TC_ARCH}" \
 && chmod +x /usr/local/bin/tailwindcss

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

CMD ["sh", "-c", "tailwindcss -c tailwind.config.js -i ./styles/input.css -o ./static/app.css --minify && uvicorn main:app --host 0.0.0.0 --port 8080"]
