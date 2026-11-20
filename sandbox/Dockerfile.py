# Python authority + the sandbox's init script and fake CRM app.
FROM python:3.15-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ src/
COPY policies/ policies/
RUN pip install --no-cache-dir . && rm -rf /root/.cache
# train the sandbox's own risk model from the simulated incidents (about 30 s); the production model is Enterprise
RUN authority train --out /app/artifacts --train-worlds 12 --test-worlds 4 > /dev/null
COPY sandbox/init.py sandbox/app.py sandbox/check_flags.py /sandbox/
USER 65532:65532
