# SPDX-License-Identifier: Apache-2.0
ARG BASE=localhost:5000/alpine:chunked
FROM ${BASE}
ARG GREETING=hello
RUN echo "$GREETING from the build" > /greeting
CMD ["sh", "-c", "cat /greeting; echo web-started; exec sleep 3600"]
