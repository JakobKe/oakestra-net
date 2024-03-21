FROM python:3.8.5-slim-buster
LABEL org.opencontainers.image.source https://github.com/oakestra/oakestra-net

ADD requirements.txt /
RUN apt-get update \
    && apt-get install -y g++ \
    && apt-get install -y --no-install-recommends gcc musl-dev linux-libc-dev libc6-dev \
    && apt-get update -y && apt-get install apt-file -y && apt-file update && apt-get install -y python3-dev build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && pip install -r requirements.txt \
    && apt-get purge -y --auto-remove gcc musl-dev linux-libc-dev libc6-dev

ADD . /

ENV FLASK_ENV=development
# TRUE for verbose logging
ENV FLASK_DEBUG=TRUE


EXPOSE 10200

CMD ["python", "service_manager.py"]
