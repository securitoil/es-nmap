FROM python:3-alpine

# Allows you to add additional packages via build-arg
ARG ADDITIONAL_PACKAGE

# Alternatively use ADD https:// (which will not be cached by Docker builder)
RUN apk --no-cache add curl ${ADDITIONAL_PACKAGE} \
    && echo "Pulling watchdog binary from Github." \
    && curl -sSL https://github.com/openfaas/faas/releases/download/0.9.6/fwatchdog > /usr/bin/fwatchdog \
    && chmod +x /usr/bin/fwatchdog \
    && apk del curl --no-cache

WORKDIR /opt/app/

COPY index.py           .
COPY requirements.txt   .

RUN pip install -r requirements.txt

RUN mkdir -p function
RUN touch ./function/__init__.py

WORKDIR /opt/app/function/
COPY function/requirements.txt	.
RUN pip install -r requirements.txt

WORKDIR /opt/app/

COPY function           function

ENV fprocess="python3 index.py"
EXPOSE 8080

HEALTHCHECK --interval=3s CMD [ -e /tmp/.lock ] || exit 1

CMD ["fwatchdog"]
