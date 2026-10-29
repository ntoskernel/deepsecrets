FROM python:3.13.1-slim-bookworm

ENV PROJECT_ROOT=/app
WORKDIR $PROJECT_ROOT

# git for the agent docs and dsbench's `git archive` of release trees; compilers for wheels without a binary build
RUN apt-get update \
    && apt-get install -y --no-install-recommends git gcc g++ \
    && rm -rf /var/lib/apt/lists/*

# Root CAs: the host's whole trust store (initialize.sh copies it into certs/) and every other PEM file in certs/, so
# pip, git and Node trust what the host trusts. Each certificate goes in as its own file where update-ca-certificates
# reads them: a feature that runs it again rebuilds the bundle, and anything only appended to the bundle would be lost.
# Node reads its own store unless told otherwise; devcontainer.json also sets NODE_OPTIONS=--use-openssl-ca
COPY .devcontainer/certs/ /tmp/certs/
RUN find /tmp/certs -type f ! -name '.*' -exec awk ' \
        /-----BEGIN CERTIFICATE-----/ { n++; out = sprintf("/usr/local/share/ca-certificates/devcontainer-%04d.crt", n); inside = 1 } \
        inside { print > out } \
        /-----END CERTIFICATE-----/ { inside = 0; close(out) }' {} + \
    && rm -rf /tmp/certs \
    && update-ca-certificates
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

# Dependencies exactly as poetry.lock pins them, into the system interpreter, at build time: the container's user
# cannot write site-packages later. The source is not copied in; the bind mount at /app supplies it
RUN pip install --no-cache-dir poetry
COPY pyproject.toml poetry.lock $PROJECT_ROOT/
RUN poetry config virtualenvs.create false \
    && poetry install --no-root --with test,dev \
    && rm -rf /root/.cache/pypoetry

# puppetparser caches its PLY parse table beside its own code. Generate it here, as root: where the user cannot write
# site-packages every Puppet probe rebuilds it (about 1 s each, KI-TOK-46) and the suite takes minutes instead of 37 s
RUN python -c "from puppetparser.parser import parse; parse('class a {}')" \
    && python -c "import os, puppetparser; assert os.path.exists(os.path.join(os.path.dirname(puppetparser.__file__), 'parsetab.py'))"

# dsbench's places: mount points that still work as empty named volumes, and where dsbench finds them
RUN mkdir -p /bench/data /bench/home /cache && chmod 1777 /bench/home /cache
ENV DSBENCH_DATA=/bench/data \
    DSBENCH_HOME=/bench/home \
    DSBENCH_TOOL_CWD=/app \
    DSBENCH_CACHE=/cache
