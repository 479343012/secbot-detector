FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget unzip ruby-full build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Go → subfinder / katana / gobuster
RUN wget -q https://go.dev/dl/go1.23.4.linux-amd64.tar.gz -O /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/OJ/gobuster/v3@latest

# nuclei + 模板(适配器路径 ~/nuclei-templates = 容器内 /root/nuclei-templates)
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip \
    && unzip -o nuclei_3.3.7_linux_amd64.zip -d /usr/local/bin/ \
    && rm nuclei_3.3.7_linux_amd64.zip \
    && chmod +x /usr/local/bin/nuclei \
    && nuclei -update-templates
# Ruby 工具链
RUN apt-get update && apt-get install -y --no-install-recommends whatweb && \
    apt-get clean && rm -rf /var/lib/apt/lists/*


RUN gem install wpscan --no-document

# testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl \
    && ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY scripts ./scripts
EXPOSE 8001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]