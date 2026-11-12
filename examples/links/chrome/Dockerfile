# A headless Chromium service box for links (examples/links/README.md). Built on the agent image, so it
# has wicket-entry (with the link addresses) and socat, which wicket uses to reach into the box.
#   docker build -t wicket/chrome:links examples/links/chrome
ARG BASE=wicket/claude-code:links
FROM ${BASE}
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends chromium fonts-liberation \
 && rm -rf /var/lib/apt/lists/*
