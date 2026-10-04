# syntax=docker/dockerfile:1
#
# The agent-threat-model CLI (atm) as an image. Build and run with:
#   docker build -t agent-threat-model .
#   docker run --rm -v "$PWD:/work" agent-threat-model analyse system.yaml
#
# The base image is pinned by digest (python:3.12-slim, multi-arch index).
ARG PYTHON_IMAGE=python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

# Build the project wheel and its dependency wheels in a throwaway stage, so the build backend
# never reaches the runtime image and the runtime install needs no network.
FROM ${PYTHON_IMAGE} AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY agent_threat_model/ agent_threat_model/
RUN pip wheel --wheel-dir /wheels .

FROM ${PYTHON_IMAGE}
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="agent-threat-model" \
      org.opencontainers.image.description="Deterministic, offline STRIDE and OWASP threat modelling for LLM-agent systems described in YAML" \
      org.opencontainers.image.source="https://github.com/basitalisandhu/agent-threat-model" \
      org.opencontainers.image.url="https://github.com/basitalisandhu/agent-threat-model" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install --no-index --find-links /wheels agent-threat-model \
 && useradd --uid 1000 --user-group --no-create-home --shell /usr/sbin/nologin app
# Mount the directory holding the system YAML at /work; relative paths resolve from there.
WORKDIR /work
USER 1000:1000
ENTRYPOINT ["atm"]
CMD ["--help"]
