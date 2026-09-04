# One shared image for every service in the sandbox (remote, all three
# actors, all three chaos agents, the verifier) — differentiated purely by
# `command:`/environment in docker-compose.yml, not by separate images.
# Fewer moving parts to get wrong when nobody can run this until the user
# tries it (see specs/chaotests/01-sandbox.md's Status note).
#
# Builds securegit from the *local working tree* (not a published version),
# so the sandbox always exercises exactly the code currently checked out —
# specs/chaotests/01-sandbox.md's Orchestration section requires this.
#
# Build context is the repository root (see docker-compose.yml), not this
# directory, because this stage needs `src/` and `package.json` from there.

FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* tsconfig.json tsconfig.build.json ./
RUN npm ci
COPY src ./src
RUN npm run build

FROM node:20-alpine
# git-daemon is a separate Alpine package from git itself — Alpine splits
# `git daemon` out (confirmed via `apk info -L git`, which does not list
# it; `git-daemon` does). Without it `remote`'s `git daemon` invocation
# fails immediately with "git: 'daemon' is not a git command" and the
# service never actually listens on :9418 — every other service's clone/
# fetch/push then times out waiting for a remote that was never there.
RUN apk add --no-cache git git-daemon bash coreutils iptables iproute2 procps
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
RUN printf '#!/bin/sh\nexec node /app/dist/bin/securegit.js "$@"\n' > /usr/local/bin/securegit \
    && chmod +x /usr/local/bin/securegit

COPY chaos/lib /chaos/lib
COPY chaos/actors /chaos/actors
COPY chaos/agents /chaos/agents
COPY chaos/remote /chaos/remote
COPY chaos/verifier /chaos/verifier

# Every role sets HOME explicitly in docker-compose.yml — this default only
# covers ad-hoc `docker run`/debugging.
ENV HOME=/home/sandbox
RUN mkdir -p /home/sandbox
