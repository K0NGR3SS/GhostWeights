# GhostWeights
**The Open Source Shadow AI Discovery Tool for AWS**

![Version](https://img.shields.io/badge/version-1.0-blue)
![Go Version](https://img.shields.io/badge/go-1.24+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/license-MIT-green)
![Category](https://img.shields.io/badge/Pentesting-red)
![Platform](https://img.shields.io/badge/Cloud-AWS-orange?logo=amazon-aws)

## What is GhostWeights?
**GhostWeights** is a specialized cloud security tool written in Go. It hunts for **"Shadow AI"**—unauthorized AI/ML workloads running in your AWS environment.

In 2026, developers frequently deploy powerful LLMs (like Llama 3, Mistral) or AI tools (Streamlit, Ray) on EC2 instances, often bypassing security controls. These "Shadow AI" endpoints can expose your organization to:
- **Remote Code Execution (RCE)** (e.g., exposed Ollama APIs).
- **Data Exfiltration** (publicly accessible RAG datasets).
- **Massive Cloud Bills** (forgotten GPU instances running 24/7).

GhostWeights scans your infrastructure to find these artifacts before attackers do.

## Key Features (v1.0)
- **Network Recon:** Scans EC2 Security Groups for specific "AI Signature" ports:
  - `11434` (Ollama)
  - `8501` (Streamlit)
  - `8265` (Ray Dashboard)
  - `7860` (Gradio / HuggingFace)
  - `8000` (vLLM / FastChat)
- **Deep AI Scanning (SSM):** Executes forensic checks inside instances to:
  - Detect **NVIDIA GPUs** (finds hidden training nodes).
  - Identify running models (e.g., "Llama-3-8b") by inspecting process arguments.
  - Find **vLLM** and **Ollama** servers running on non-standard ports.
- **Interactive UI:** Features a modern CLI with spinners, progress tables, and interactive region selection.
- **Risk Grading:** Automatically categorizes findings by risk level (Critical, High, Medium).

## Example Output (Risks Detected)
```text
Phase 1: Initialization
✓ Connected to AWS (us-east-1)

Phase 2: Discovery & Analysis
✓ Scan Complete

🚨 Found 3 potential issues:

Risk      Service                 Instance ID          Description                                Evidence
CRITICAL  Ollama API              i-0a1b2c3d4e5f6g7h8  Active Ollama API                          Port 11434 open to 0.0.0.0/0
HIGH      vLLM Inference Server   i-11223344556677889  Serving model: Llama-3-8b on GPU (T4)      Cmd: python -m vllm.entrypoints...
MED       Suspicious Process      i-99887766554433221  Potential AI workload                      Cmd: python3 train.py --epochs 10
```

## Installation

```bash
git clone https://github.com/K0NGR3SS/ghostweights.git
cd ghostweights
go mod tidy
go run ./cmd/ghostweights --help
```

## Usage

### Show help
```bash
go run ./cmd/ghostweights –-help
```
### Scan (interactive region prompt)
#### Runs a scan and prompts for AWS Region if you don’t pass –-region
```bash
go run ./cmd/ghostweights scan
```
### Scan a specific region (non-interactive)
```bash
go run ./cmd/ghostweights scan –-region eu-west-1
```
### Deep scan (SSM process hunting)
#### Enables AWS SSM inspection of running processes (requires SSM Agent + permissions like ssm:SendCommand on targets).
```bash
go run ./cmd/ghostweights scan –-deep
```
### Deep scan in a specific region (recommended for CI)
```bash
go run ./cmd/ghostweights scan –-region eu-west-1 –-deep
```
## Generate shell autocompletion
### zsh
```bash
go run ./cmd/ghostweights completion zsh
```
### bash
```bash
go run ./cmd/ghostweights completion bash
```
### fish
```bash
go run ./cmd/ghostweights completion fish
```
### powershell
```bash
go run ./cmd/ghostweights completion powershell
```
## Print version
```bash
go run ./cmd/ghostweights version
```
## Legal disclaimer

This tool is intended only for authorized security testing and defensive security auditing on systems you own or have explicit permission to assess.
Unauthorized scanning or exploitation may be illegal; you are responsible for complying with all applicable laws, contracts, and cloud provider policies.
The software is provided "as is", without warranty, and the authors are not liable for any damages resulting from use or misuse.