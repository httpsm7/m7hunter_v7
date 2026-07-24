# M7Hunter V7 — Production Dockerfile
# Python 3.13 + Go 1.24 compatible
# MilkyWay Intelligence | AUTHORIZED USE ONLY

ARG GO_VERSION=1.24.3
ARG PYTHON_VERSION=3.13

# ── Stage 1: Go tools ─────────────────────────────────────────────────
FROM golang:${GO_VERSION}-bookworm AS go-builder

ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
ENV CGO_ENABLED=0
ENV GOPROXY=https://proxy.golang.org,direct

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest   2>/dev/null && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest               2>/dev/null && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest                 2>/dev/null && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest          2>/dev/null && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest            2>/dev/null && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest             2>/dev/null && \
    go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>/dev/null && \
    go install github.com/projectdiscovery/alterx/cmd/alterx@latest             2>/dev/null && \
    go install github.com/hakluke/hakrawler@latest                              2>/dev/null && \
    go install github.com/lc/gau/v2/cmd/gau@latest                             2>/dev/null && \
    go install github.com/tomnomnom/waybackurls@latest                          2>/dev/null && \
    go install github.com/tomnomnom/anew@latest                                 2>/dev/null && \
    go install github.com/tomnomnom/qsreplace@latest                            2>/dev/null && \
    go install github.com/tomnomnom/gf@latest                                   2>/dev/null && \
    go install github.com/tomnomnom/assetfinder@latest                          2>/dev/null && \
    go install github.com/hahwul/dalfox/v2@latest                              2>/dev/null && \
    go install github.com/sensepost/gowitness@latest                            2>/dev/null && \
    go install github.com/sensepost/subzy@latest                                2>/dev/null && \
    go install github.com/ffuf/ffuf/v2@latest                                   2>/dev/null && \
    go install github.com/gospiderteam/gospider@latest                          2>/dev/null && \
    go install github.com/trufflesecurity/trufflehog/v3@latest                  2>/dev/null && \
    echo "Go tools built ✓"

# ── Stage 2: Final image ──────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim-bookworm AS final

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PATH="/go/bin:/home/m7/.local/bin:$PATH"

# System packages
RUN apt-get update -qq && apt-get install -yq --no-install-recommends \
    nmap masscan dnsutils curl wget git jq tor proxychains4 \
    chromium chromium-driver \
    libssl-dev libffi-dev build-essential ca-certificates \
    libxml2-dev libxslt1-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy Go binaries from builder
COPY --from=go-builder /go/bin /go/bin

# Create non-root user
RUN useradd -m -s /bin/bash m7 && \
    mkdir -p /home/m7/.m7hunter && chmod 700 /home/m7/.m7hunter

WORKDIR /app

# Install Python dependencies — Python 3.13 compatible
COPY requirements.txt .

# Upgrade pip + setuptools first (critical for Python 3.13)
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt && \
    python -m playwright install chromium --with-deps 2>/dev/null || true

# Copy source
COPY . .

# Nuclei templates
RUN nuclei -update-templates -silent 2>/dev/null || true

# GF patterns
RUN git clone --quiet --depth=1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gfp 2>/dev/null && \
    mkdir -p /home/m7/.gf && cp /tmp/gfp/*.json /home/m7/.gf/ && rm -rf /tmp/gfp || true

RUN chmod +x m7hunter.py && \
    ln -sf /app/m7hunter.py /usr/local/bin/m7hunter && \
    chown -R m7:m7 /app /home/m7

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import httpx, pydantic; print('ok')" || exit 1

USER m7
EXPOSE 8719
ENTRYPOINT ["python3", "m7hunter.py"]
CMD ["--help"]
