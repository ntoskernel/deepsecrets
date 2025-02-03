FROM python:3.13.1-slim-bookworm

ENV PROJECT_ROOT /app
WORKDIR $PROJECT_ROOT

RUN apt update && apt install -y gcc g++
RUN pip install poetry

COPY pyproject.toml $PROJECT_ROOT/
COPY *.lock $PROJECT_ROOT/

RUN poetry config virtualenvs.create false
RUN poetry update && poetry install --no-root

COPY . $PROJECT_ROOT

RUN PATH="$PROJECT_ROOT/bin:$PATH"
RUN PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"