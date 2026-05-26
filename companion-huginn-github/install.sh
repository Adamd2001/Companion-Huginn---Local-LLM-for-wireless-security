#!/usr/bin/env bash
# Companion Huginn - first-time setup script (Linux / macOS).
#
# Creates a local Python virtual environment, installs runtime dependencies,
# verifies that Ollama is installed, and stages a .env from .env.example so
# you can fill in your configuration.

set -e

echo "==> Companion Huginn setup"
echo

# ──────────────────────────────────────────────────────────────────────────
# 1. Python 3 check
# ──────────────────────────────────────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 was not found on PATH."
    echo "       Install Python 3.10+ from your package manager or https://www.python.org/downloads/"
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print("{}.{}".format(sys.version_info[0], sys.version_info[1]))')
echo "Found python3 ${PY_VERSION}"

# ──────────────────────────────────────────────────────────────────────────
# 2. Virtual environment
# ──────────────────────────────────────────────────────────────────────────
if [ ! -d ".venv" ]; then
    echo "==> Creating virtual environment in .venv/"
    python3 -m venv .venv
else
    echo "==> Reusing existing .venv/"
fi

# shellcheck disable=SC1091
. .venv/bin/activate

# ──────────────────────────────────────────────────────────────────────────
# 3. Python dependencies
# ──────────────────────────────────────────────────────────────────────────
echo "==> Upgrading pip"
python -m pip install --upgrade pip >/dev/null

echo "==> Installing requirements.txt"
python -m pip install -r requirements.txt

# ──────────────────────────────────────────────────────────────────────────
# 4. Ollama presence check (explicit exit on missing, do not rely on set -e)
# ──────────────────────────────────────────────────────────────────────────
if ! command -v ollama >/dev/null 2>&1; then
    echo
    echo "ERROR: Ollama was not found on PATH."
    echo "       Companion Huginn talks to a local Ollama instance for inference."
    echo "       Install it from: https://ollama.com/download"
    echo "       Then re-run this script."
    exit 1
fi
echo "==> Ollama detected: $(ollama --version 2>/dev/null | head -n 1)"

# ──────────────────────────────────────────────────────────────────────────
# 5. .env staging
# ──────────────────────────────────────────────────────────────────────────
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    echo "==> Creating .env from .env.example"
    cp .env.example .env
    echo "    Edit .env to set your local paths and toggles."
elif [ -f ".env" ]; then
    echo "==> .env already exists - leaving it alone."
fi

# ──────────────────────────────────────────────────────────────────────────
# 6. Next steps
# ──────────────────────────────────────────────────────────────────────────
cat <<'EOF'

Setup complete.

Next steps:

  1. Pull the base Mistral model into Ollama:

         ollama pull mistral

  2. Obtain the fine-tuned huginn-final model.
     ⚠️  huginn-final is NOT bundled in this repository.

     This project expects an Ollama model tagged `huginn-final` (a merged
     LoRA-fine-tuned variant of Mistral 7B Instruct, quantized to Q4_K_M).
     Distribution of the GGUF / Modelfile is TBD - see README.md → "Model"
     for the latest options. Until then, you can fall back to the included
     Modelfile recipe:

         ollama create huginn-final -f Modelfile

     and update config/config.yaml -> ollama.model_name if your local tag
     differs.

  3. Export HUGINN_HOME (so the runtime can find captures/, logs/, memory/):

         export HUGINN_HOME=$(pwd)

  4. (Optional) Generate an SSH key for the WiFi Pineapple, drop it under
     keys/, and point config/pineapple.yaml -> identity_file at it:

         ssh-keygen -t ed25519 -f keys/pineapple_ed25519 -N ""

  5. Activate the venv and launch the agent:

         source .venv/bin/activate
         python agent.py

EOF
