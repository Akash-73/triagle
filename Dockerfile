# ---- 1. the tests ------------------------------------------------------------
# The image cannot be built unless every test passes. A deploy builds the
# image, so a change that breaks a test never goes live.
FROM python:3.12-slim AS test
WORKDIR /app
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt
COPY . .
RUN python -m pytest -q -x && touch /tests-passed

# ---- 2. what runs -------------------------------------------------------------
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# The line below is what ties this stage to the one above.
COPY --from=test /tests-passed /tmp/tests-passed
# An unprivileged user for the app, owning only the folder it writes its own log to.
RUN rm -rf tests requirements-dev.txt \
    && groupadd --system --gid 10001 triagle \
    && useradd --system --uid 10001 --gid 10001 --home-dir /app --no-create-home triagle \
    && mkdir -p /app/data && chown triagle:triagle /app/data \
    && chmod +x /app/scripts/start.sh
EXPOSE 8000
# start.sh gives up root before the app starts (see the file for the one case in which it cannot)
CMD ["/app/scripts/start.sh"]
