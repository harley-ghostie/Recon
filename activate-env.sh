#!/usr/bin/env bash
# =============================================================================
# activate-env.sh — Ativa ambiente isolado do recon (Kali Linux)
# =============================================================================
# Uso: source ./activate-env.sh
#      (configurado automaticamente pelo install.sh no .zshrc/.bashrc)
# =============================================================================

_RECON_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export RECON_HOME="${_RECON_ROOT}"
export GOPATH="${_RECON_ROOT}/.go"
export GOBIN="${_RECON_ROOT}/tools/bin"

# Python venv (uro) — ativar ANTES, depois tools/bin tem prioridade
if [[ -f "${_RECON_ROOT}/venv/bin/activate" ]]; then
    # shellcheck source=/dev/null
    source "${_RECON_ROOT}/venv/bin/activate"
fi

# tools/bin SEMPRE primeiro (evita conflito httpx Python vs ProjectDiscovery)
export PATH="${_RECON_ROOT}/tools/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"

# Binário explícito do httpx ProjectDiscovery
export HTTPX_BIN="${_RECON_ROOT}/tools/bin/httpx"

# GF patterns isolados ao projeto
if [[ -d "${_RECON_ROOT}/.gf-home" ]]; then
    export HOME="
