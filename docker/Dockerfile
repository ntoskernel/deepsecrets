# The DeepSecrets image that .github/workflows/release-docker.yml pushes. It installs a published release from PyPI,
# not this checkout, and its build context is docker/, so nothing else from the repository reaches it:
#   docker build --build-arg DEEPSECRETS_VERSION=2.2.0 docker
FROM python:3.14-slim

ARG DEEPSECRETS_VERSION
RUN pip install --no-cache-dir "deepsecrets==${DEEPSECRETS_VERSION}"

WORKDIR /src
CMD ["deepsecrets", "--help"]
