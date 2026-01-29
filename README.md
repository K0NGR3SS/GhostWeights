# GhostWeights
**Shadow AI Discovery Tool for AWS**

![Version](https://img.shields.io/badge/version-1.1-blue)
![Go Version](https://img.shields.io/badge/go-1.24+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/license-MIT-green)

## What is GhostWeights?

GhostWeights hunts for **unauthorized AI/ML workloads** running in your AWS environment. It finds Shadow AI before attackers do - exposed APIs, forgotten GPU instances, and vulnerable endpoints.

**Detects:**
- Exposed Ollama, vLLM, Streamlit, Ray, Jupyter endpoints
- Running LLMs (Llama, Mistral) on EC2 instances
- AI model files on disk (.safetensors, .gguf, .bin)
- Exposed API keys in environment variables
- IMDSv1 vulnerable instances
- Public/unencrypted S3 buckets with models
- GPU instances without proper security

## Quick Start

```bash
# Clone and build
git clone https://github.com/K0NGR3SS/ghostweights.git
cd ghostweights
go mod tidy
go build -o ghostweights ./cmd/ghostweights

# Basic scan
./ghostweights scan --region us-east-1

# Deep scan (uses SSM to inspect processes)
./ghostweights scan --region us-east-1 --deep

# Scan all regions
./ghostweights scan --all-regions --deep
```

## Key Features

### Network Scanning
Checks security groups for exposed AI ports:
- `11434` - Ollama API
- `8501` - Streamlit
- `8265` - Ray Dashboard
- `7860` - Gradio/HuggingFace
- `8000` - vLLM/FastChat
- `8888` - Jupyter Notebook

### Deep Scanning (SSM)
Inspects running instances to find:
- AI model files on disk
- Running LLM processes (Llama, Mistral, etc.)
- Exposed API keys (OpenAI, Anthropic, HuggingFace)
- GPU presence (NVIDIA)
- Python AI packages (torch, transformers, vllm)
- Jupyter notebooks without authentication

### S3 Analysis
Scans buckets for:
- AI-related bucket names (model, dataset, rag, etc.)
- Public access misconfiguration
- Missing encryption
- Model files (.safetensors, .gguf, .pt, .h5)

## Usage Examples

### Export to JSON
```bash
./ghostweights scan --region us-east-1 --format json --output findings.json
```

### Export to CSV
```bash
./ghostweights scan --region us-east-1 --format csv --output findings.csv
```

### Show only critical findings
```bash
./ghostweights scan --region us-east-1 --min-risk CRITICAL
```

### Exclude specific instances
```bash
./ghostweights scan --region us-east-1 --exclude-ids i-abc123,i-def456
```

### Include S3 scanning
```bash
./ghostweights scan --region us-east-1 --s3 --deep
```

### Scan everything
```bash
./ghostweights scan --all-regions --deep --s3 --format json --output report.json
```

## Command Reference

```bash
# Show help
./ghostweights --help
./ghostweights scan --help

# Print version
./ghostweights version

# Shell completion
./ghostweights completion bash
./ghostweights completion zsh
```

### Available Flags

```
--region, -r        AWS region to scan (e.g., us-east-1)
--all-regions       Scan all AWS regions
--deep              Enable SSM deep scanning
--s3                Scan S3 buckets for AI models
--format            Output format: table, json, csv (default: table)
--output, -o        Write results to file
--min-risk          Minimum risk level: LOW, MEDIUM, HIGH, CRITICAL
--exclude-ids       Comma-separated instance IDs to skip
```

## Example Output

```
Phase 1: Initialization
✓ Connected to AWS (us-east-1)

Phase 2: Discovery & Analysis
✓ Found 157 running instances across 2 pages
✓ Scan Complete

Phase 3: Final Report
🚨 Found 8 potential issues:

Risk      Service                 Instance ID          Description                           Evidence
CRITICAL  Exposed API Key         i-0a1b2c3d4e5f6g7h8  API key in environment               OPENAI_***_KEY=sk-***abc
CRITICAL  Ollama API              i-abc123def456       Active Ollama API                    Port 11434 open to 0.0.0.0/0
HIGH      vLLM Inference Server   i-11223344556677889  Serving model: Llama-3-8b on GPU     Cmd: python -m vllm...
HIGH      AI Model Files          i-0a1b2c3d4e5f6g7h8  Found 12 model files                 Files: model.safetensors...
HIGH      S3 Bucket               my-models-bucket     Contains 25 model files (PUBLIC)     Bucket: my-models-bucket
MEDIUM    GPU Detected            i-99887766554433221  NVIDIA A100 GPU present              Potential AI workload
MEDIUM    IMDSv1 Enabled          i-xyz789             SSRF vulnerable                      HttpTokens=optional
LOW       AI Python Packages      i-0a1b2c3d4e5f6g7h8  Found 5 AI/ML packages               torch, transformers...
```

## IAM Permissions Required

Minimum policy for basic scanning:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

For deep scanning, add:
```json
{
  "Effect": "Allow",
  "Action": [
    "ssm:SendCommand",
    "ssm:GetCommandInvocation"
  ],
  "Resource": "*"
}
```

For S3 scanning, add:
```json
{
  "Effect": "Allow",
  "Action": [
    "s3:ListAllMyBuckets",
    "s3:GetBucketLocation",
    "s3:GetBucketAcl",
    "s3:GetBucketPolicy",
    "s3:GetBucketEncryption",
    "s3:ListBucket"
  ],
  "Resource": "*"
}
```

**For SSM deep scan:** Instances need SSM Agent installed and IAM role with `AmazonSSMManagedInstanceCore` policy.

## CI/CD Integration

```bash
# Fail build if critical findings exist
./ghostweights scan --region us-east-1 --format json --output findings.json

# Check for critical issues
if [ $(jq '[.[] | select(.risk=="CRITICAL")] | length' findings.json) -gt 0 ]; then
  echo "❌ CRITICAL Shadow AI findings detected!"
  exit 1
fi
```

## Scheduled Scanning

```bash
# Add to crontab for weekly scans
0 2 * * 1 /usr/local/bin/ghostweights scan --all-regions --deep --format json --output /var/log/ghostweights/$(date +\%Y\%m\%d).json
```

## What's New in v1.1

### Critical Fixes
- ✅ Fixed pagination (now handles unlimited instances)
- ✅ Added security group caching (10x faster scans)
- ✅ Better error handling and logging

### New Detections
- ✅ IMDSv1 vulnerable instances
- ✅ Model files on disk (.safetensors, .gguf, .bin)
- ✅ Exposed API keys in environment
- ✅ Python AI packages (torch, transformers, etc.)
- ✅ Jupyter notebooks without authentication
- ✅ S3 buckets with AI models
- ✅ GPU detection

### New Features
- ✅ JSON and CSV output formats
- ✅ Multi-region scanning (--all-regions)
- ✅ Risk-based filtering (--min-risk)
- ✅ Instance exclusion lists
- ✅ S3 bucket analysis

## Use Cases

**Security Auditing:** Find unauthorized AI deployments  
**Compliance:** Ensure AI workloads meet security standards  
**Cost Optimization:** Find forgotten GPU instances  
**Incident Response:** Quick assessment of Shadow AI exposure  
**Red Team:** Enumerate AI attack surface

## Legal Disclaimer

This tool is intended only for authorized security testing on systems you own or have explicit permission to assess. Unauthorized scanning may be illegal. You are responsible for complying with all applicable laws and cloud provider policies.

The software is provided "as is", without warranty.