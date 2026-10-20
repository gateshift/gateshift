# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
#
# Built from the REPOSITORY ROOT (docker-compose.yml: context ".",
# dockerfile pyapp/gateshift/Dockerfile), so the SQL jobs and the VERSION
# file are baked in beside the collector's code. The collector and the webapp
# both write the rule pipeline's identity columns; with everything baked, a
# git pull alone changes nothing at runtime and a rebuild moves both halves
# together (docs/DEVICE_IDENTITY_PLAN.md, D7).

FROM python:3.12-slim

WORKDIR /app

COPY pyapp/gateshift/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY pyapp/gateshift /app
# One VERSION file for both images: webui/VERSION is the source of truth,
# the webapp reads it as /app/VERSION and so does the collector.
COPY webui/VERSION /app/VERSION
# The schema and the pipeline jobs the collector executes: code, not data.
COPY sql /sql

CMD ["python", "-u", "main.py"]
