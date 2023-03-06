# docker build -t network . --network=host
# docker tag network:latest ydethe/network:latest
# docker push ydethe/network:latest
FROM python:3.9-bullseye

ARG DATABASE_URI
ARG HOST
ARG ROOT_PATH
ARG NB_WORKERS
ARG PORT

ENV DATABASE_URI $DATABASE_URI
ENV HOST $HOST
ENV ROOT_PATH $ROOT_PATH
ENV NB_WORKERS $NB_WORKERS
ENV PORT $PORT

SHELL ["/bin/bash", "-c"]
RUN export DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true
RUN echo "tzdata tzdata/Areas select Europe" > preseed.txt
RUN echo "tzdata tzdata/Zones/Europe select Berlin" >> preseed.txt
RUN debconf-set-selections preseed.txt
RUN apt-get update --allow-releaseinfo-change && apt-get install -yqq --no-install-recommends python3-dev python3-pip python3-venv gcc g++ gnupg2 libssl-dev libpq-dev curl libgeos-dev libpq-dev
COPY ./dist/*.whl /app/
WORKDIR /app
RUN mkdir -p log
RUN find /app -name "*.whl" -exec pip install {} \;
EXPOSE $PORT
CMD network_server --port $PORT
