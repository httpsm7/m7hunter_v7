FROM python:3.11-slim

LABEL maintainer="Sharlix <MilkyWay Intelligence>"
LABEL version="7.0"
LABEL description="M7Hunter V7 — Authorized Bug Bounty Automation"

# System deps
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    curl git wget nmap masscan sqlmap tor proxychains4 \
    golang-go ruby ruby-dev jq dnsutils build-essential \
    ca-certificates libssl-dev chromium \
    && rm -rf /var/lib/apt/lists/*

# Go tools
ENV GOPATH=/root/go
ENV PATH=$PATH:$GOPATH/bin:/usr/local/go/bin

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest            2>/dev/null || true && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest       2>/dev/null || true && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest              2>/dev/null || true && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest          2>/dev/null || true && \
    go install github.com/hahwul/dalfox/v2@latest                            2>/dev/null || true && \
    go install github.com/tomnomnom/gf@latest                                2>/dev/null || true && \
    go install github.com/tomnomnom/qsreplace@latest                         2>/dev/null || true && \
    go install github.com/lc/gau/v2/cmd/gau@latest                          2>/dev/null || true && \
    go install github.com/hakluke/hakrawler@latest                           2>/dev/null || true

# Python deps
RUN pip3 install --no-cache-dir \
    httpx[http2] \
    playwright \
    aiofiles \
    websockets \
    requests \
    aiohttp \
    && playwright install chromium --with-deps 2>/dev/null || true

# WPScan
RUN gem install wpscan --quiet 2>/dev/null || true

# App
WORKDIR /opt/m7hunter
COPY . .
RUN pip3 install --no-cache-dir -e . 2>/dev/null || true

# Non-root user
RUN useradd -m -u 1001 m7user && \
    mkdir -p /home/m7user/.m7hunter && \
    chown -R m7user:m7user /opt/m7hunter /home/m7user/.m7hunter

# Results volume
RUN mkdir -p /opt/m7hunter/results && chown m7user /opt/m7hunter/results
VOLUME ["/opt/m7hunter/results"]

USER m7user
ENV HOME=/home/m7user

ENTRYPOINT ["python3", "/opt/m7hunter/m7hunter.py"]
CMD ["--help"]
