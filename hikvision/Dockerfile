FROM python:3.8.12-slim-buster

ENV PYTHONUNBUFFERED=1 \
    APP_ROOT=/var/app

COPY requirements.txt ${APP_ROOT}/requirements.txt

RUN set -ex \
    && BUILD_PACKAGES='\
        build-essential \
        git-core \
    ' \
    && RUNTIME_PACKAGES=' \
        curl \
    ' \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ${BUILD_PACKAGES} ${RUNTIME_PACKAGES} \
    && pip install --no-cache-dir -r ${APP_ROOT}/requirements.txt \
    && apt-get remove -y ${BUILD_PACKAGES} \
    && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
    && rm -rf /var/lib/apt/lists/* \
    \
    && find /usr/local -depth \
        \( \
            \( -type f -a \( -name '*.pyc' -o -name '*.pyo' \) \) \
        \) -exec rm -rf '{}' +

COPY docker-entrypoint.sh /usr/local/bin/default-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/default-entrypoint.sh"]

COPY ./src/ ${APP_ROOT}

WORKDIR ${APP_ROOT}

EXPOSE 21

CMD ["python", "gateway.py"]

