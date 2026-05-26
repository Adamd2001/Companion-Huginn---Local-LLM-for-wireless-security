# Companion Huginn

LLM-first companion for authorized Wi-Fi security audits - talks to a local Ollama model, routes deterministic backend tools (Hak5 WiFi Pineapple, hashcat, hcxdumptool, tshark, nmap) through an allowlist, and reports only on what the tools actually observed.

> ⚠️ **Authorized use only.** Companion Huginn drives real, intrusive wireless tooling (monitor mode, deauthentication, ARP spoofing, password cracking). Use it **only** against networks you own or have explicit, written permission to test. The maintainers accept no responsibility for misuse.

---

## Overview

- **LLM-first + deterministic tool routing.** The operator chats with the model in natural language. The model decides whether the request needs live data and, if so, emits a single JSON tool-call object. A deterministic Python orchestrator validates that call against a fixed schema and dispatches it. The model never executes anything by itself.
- **WiFi Pineapple (Mark VII) first-class integration.** SSH-based passive scans, channel-locked captures, monitor-mode bring-up, `aireplay-ng` deauth bursts, `hcxdumptool` PMKID capture (with PMF fallback), `arpspoof` (Pineapple-side with sysctl save/restore), `nmap` discovery and staged subnet mapping - all routed through the Pineapple's upstream interface.
- Observation-gated answers - the model can only summarize what tool results actually contained.
- Allowlisted apps / commands / file roots configured in `config/*.yaml`.
- Live unencrypted-traffic scan with HTTP credential extraction, plaintext-protocol detection, and reconstructed HTTP media (JPEG/PNG/MP4/WebM/…) wrapped in a Markdown + HTML report.
- Single-pass capture-to-crack: `crack_wifi_pcap` extracts a handshake or PMKID, picks a wordlist, and runs hashcat in one tool call.

## Model

This version of Companion Huginn is configured for **`huginn-final`** - a merged LoRA-fine-tuned variant of Mistral 7B Instruct, quantized to Q4_K_M and served by a local Ollama instance. The config entry that drives this is in `config/config.yaml`:

```yaml
ollama:
  url: "http://127.0.0.1:11434/api/generate"
  model_name: "huginn-final"
```

### Obtaining `huginn-final`

> **TBD - distribution is not yet finalized.**
>
> The merged GGUF for `huginn-final` is **not** bundled in this repository (model weights exceed GitHub's per-file limits). Likely future distribution options are a Hugging Face repository hosting the GGUF, or a Modelfile-only release that rebuilds the adapter on top of the base.
>
> Until that page exists, two stopgaps:
>
> 1. **Fall back to the included Modelfile.** The repository's `Modelfile` builds a system-prompted variant directly on top of base Mistral. Build it as `huginn-final` so the config keeps working:
>
>    ```bash
>    ollama pull mistral
>    ollama create huginn-final -f Modelfile
>    ```
>
>    This gives you the prompt/persona but not the fine-tuned weights.
>
> 2. **Point at any other Ollama tag.** Edit `config/config.yaml` → `ollama.model_name` to whatever local tag you have built or pulled (`mistral`, your own fine-tune, etc.).

The included `training/` directory currently holds **placeholder scripts** (`train_peft.py`, `merge_lora.py`, `merge_lora_cpu.py`, `test_adapter.py`) - the real LoRA training pipeline is maintained out-of-tree.

## Installation

Prerequisites:

- Linux (Kali recommended) or macOS
- Python 3.10+
- [Ollama](https://ollama.com/download) installed and running locally
- (Optional, for hardware-driven tools) Hak5 WiFi Pineapple Mark VII reachable over SSH, plus standard wireless toolchain (`aircrack-ng`, `hashcat`, `hcxdumptool`, `hcxpcapngtool`, `tshark`, `nmap`)

Clone and run the installer:

```bash
git clone https://github.com/YOUR-USERNAME/companion-huginn-github.git
cd companion-huginn-github
./install.sh
```

`install.sh` creates a `.venv/`, installs `requirements.txt`, verifies that the `ollama` binary is on `PATH` (exits if not), and stages `.env` from `.env.example` on first run.

After it finishes:

```bash
ollama pull mistral
ollama create huginn-final -f Modelfile   # or pull your distributed huginn-final tag
export HUGINN_HOME=$(pwd)
source .venv/bin/activate
python agent.py
```

## Configuration

Two configuration layers:

- **`.env`** - machine-local environment variables (see `.env.example`).
- **`config/*.yaml`** - committed defaults that ship with the repo.

### Environment variables (`.env.example`)

| Variable             | Default                                        | Purpose                                                                                       |
| -------------------- | ---------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `HUGINN_HOME`        | `/home/USER/Desktop/companion-huginn-github`   | Root for `config/`, `captures/`, `logs/`, `memory/`, `reports/`. Set this to the clone path.  |
| `HUGINN_CONFIRM`     | *(unset)*                                      | Set to `approved` to allow controlled actions when `policy.execution.require_confirmation_env` is `true`. |
| `HUGINN_SHOW_SECRETS`| `1`                                            | `1` = print cleartext credentials in reports, `0` = mask them.                                |

### YAML configuration

| File                    | Drives                                                                                |
| ----------------------- | ------------------------------------------------------------------------------------- |
| `config/config.yaml`    | Ollama URL, model tag, decoding temperatures, agent routing thresholds.               |
| `config/pineapple.yaml` | Pineapple SSH target (`host`, `user`, `identity_file`), capture dir, monitor iface.   |
| `config/policy.yaml`    | Confirmation gating, allowed filesystem read roots, max bytes per read.               |
| `config/allowlist.yaml` | Local GUI apps and shell commands the orchestrator may launch.                        |

### Pineapple SSH key

The Pineapple integration uses SSH key auth - there is no password-based fallback. Generate a key and copy the public half to the Pineapple, then point `config/pineapple.yaml` → `identity_file` at the private key:

```bash
ssh-keygen -t ed25519 -f keys/pineapple_ed25519 -N ""
ssh-copy-id -i keys/pineapple_ed25519.pub root@172.16.42.1
```

The default `keys/` directory is gitignored - never commit a real private key.

## Usage

Companion Huginn is conversational. Launch it and ask in plain English:

```bash
python agent.py
```

A few short examples to try once it's running (the model decides which tool, if any, to invoke):

```text
> check pineapple status
> show nearby SSIDs
> deep analyze SSID "ExampleNet" for 180 seconds
> capture the latest pcap and tell me if there is a usable handshake
> deauth and capture handshake for AA:BB:CC:DD:EE:FF on channel 6
> crack the latest pcap with the rockyou wordlist
> live unencrypted scan for 120 seconds over the pineapple
> generate a report titled "Site survey 2026-05-21"
```

One-shot mode is also available for scripting:

```bash
python agent_cli.py --once "check pineapple status"
```

To enable controlled actions (captures, deauth, arpspoof) without per-action confirmation, opt in via the env var while the corresponding policy is enabled in `config/policy.yaml`:

```bash
export HUGINN_CONFIRM=approved
```

## Project structure

```
companion-huginn-github/
├── agent.py                    # primary entry point - interactive REPL
├── agent_cli.py                # CLI router + LLM glue (one-shot and interactive)
├── huginn_cli.py               # alias entry point
├── huginn_orchestrator.py      # compatibility wrapper for one-shot tool calls
├── orchestrator.py             # tool-call extraction + dispatch
├── core/
│   ├── app_paths.py            # HUGINN_HOME resolution + runtime dir helpers
│   ├── config_loader.py        # YAML loader for config/
│   ├── llm_client.py           # thin Ollama HTTP client
│   ├── prompt_builder.py       # system + per-turn prompt assembly
│   ├── session_store.py        # per-session memory log
│   └── tool_registry.py        # tool schema, registry, and per-action handlers
├── tools/
│   ├── advanced_tools.py       # finding + report writing
│   ├── latest_pcap.py          # newest capture in captures/
│   ├── local_tools.py          # local Kali tools: hashcat, john, arpspoof, nmap, …
│   ├── pcap_summarize.py       # short tshark summary
│   ├── pineapple_helpers.py    # SSH ops, ssid analysis, subnet map, arpspoof
│   ├── pineapple.py            # remote tcpdump capture lifecycle
│   ├── tshark_deep.py          # deep tshark review
│   ├── tshark_summarize.py     # short tshark summary backend
│   ├── unencrypted_credentials.py  # cleartext credential extraction
│   ├── unencrypted_media_report.py # HTTP media reconstruction + report
│   └── wifi_deep_report.py     # client confidence + EAPOL analysis
├── training/                   # placeholder LoRA scripts (real pipeline out-of-tree)
├── config/                     # YAML configuration (see Configuration)
├── captures/  reports/  logs/  memory/  keys/   # runtime dirs (kept empty in git)
├── Modelfile                   # Ollama recipe for the system-prompted base
├── train.jsonl                 # tiny training-format example
├── requirements.txt
├── install.sh
├── .env.example
├── .gitignore
└── README.md
```

## License

MIT License

Copyright (c) 2026 Adamd2001

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
