FROM docker:cli AS docker

FROM python:3.12-slim
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
RUN pip install --no-cache-dir "redis>=5.0"
COPY autoscaler.py /autoscaler.py
CMD ["python", "-u", "/autoscaler.py"]
