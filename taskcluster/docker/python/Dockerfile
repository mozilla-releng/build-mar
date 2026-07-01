# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

ARG PYTHON_VERSION

FROM ghcr.io/astral-sh/uv:0.11.26@sha256:3d868e555f8f1dbc324afa005066cd11e1053fc4743b9808ca8025283e65efa5 AS uv
FROM python:$PYTHON_VERSION-slim
LABEL maintainer="Release Engineering <release@mozilla.com>"

COPY --from=uv /uv /bin

ENV UV_LINK_MODE=copy

VOLUME /builds/worker/checkouts
VOLUME /builds/worker/.cache

# Add worker user
RUN mkdir -p /builds && \
    useradd -d /builds/worker -s /bin/bash -m worker && \
    mkdir /builds/worker/artifacts && \
    chown -R worker:worker /builds/worker

# %include-run-task

RUN apt-get update \
 && apt-get install -y --reinstall ca-certificates \
 && apt-get install -y --force-yes --no-install-recommends \
    build-essential \
    mercurial \
    git

ENV SHELL=/bin/bash \
    HOME=/builds/worker \
    PATH=/builds/worker/.local/bin:$PATH

# Set a default command useful for debugging
CMD ["/bin/bash", "--login"]
