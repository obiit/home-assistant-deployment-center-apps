FROM ghcr.io/home-assistant/base-python:3.14-alpine3.24-2026.08.0

ARG BUILD_VERSION=0.1.1
ARG BUILD_ARCH=amd64

RUN apk add --no-cache openssl

WORKDIR /opt/hadc-companion
COPY hadc_companion/ ./hadc_companion/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HADC_CONFIG_ROOT=/homeassistant \
    HADC_DATA_ROOT=/data \
    HADC_LISTEN_HOST=0.0.0.0 \
    HADC_LISTEN_PORT=18091 \
    HADC_COMPANION_VERSION=${BUILD_VERSION}

LABEL \
    io.hass.version="${BUILD_VERSION}" \
    io.hass.type="app" \
    io.hass.arch="${BUILD_ARCH}" \
    io.hass.name="HADC Companion" \
    io.hass.description="Read-only companion for Home Assistant Deployment Center" \
    io.hass.url="https://github.com/obiit/home-assistant-deployment-center-apps" \
    org.opencontainers.image.title="HADC Companion" \
    org.opencontainers.image.description="Read-only Home Assistant configuration inventory service" \
    org.opencontainers.image.source="https://github.com/obiit/home-assistant-deployment-center-apps"

EXPOSE 18091
CMD ["python3", "-m", "hadc_companion"]
