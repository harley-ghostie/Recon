#!/usr/bin/env bash
# =============================================================================
# install.sh - Instalador único para Kali Linux
# =============================================================================
# Uso (um único comando):
#   cd /caminho/recon && chmod +x install.sh && ./install.sh
#
# Instala automaticamente:
#   - Pacotes apt base do Kali (curl, jq, go, python3-venv...)
#   - Ferramentas ProjectDiscovery em tools/bin (subfinder, httpx, nuclei, katana)
#   - venv Python com uro
#   - Ferramentas Go em tools/bin (waybackurls, hakrawler, gf)
#   - Binário dalfox em tools/bin
#   - GF patterns + templates Nuclei
#   - Configura PATH no .zshrc e .bashrc do Kali
# =============================================================================

set -uo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TOOLS_BIN="${SCRIPT_DIR}/tools/bin"
readonly VENV_DIR="${SCRIPT_DIR}/venv"
readonly GF_PATTERNS="${SCRIPT_DIR}/gf-patterns"
readonly GO_PATH="${SCRIPT_DIR}/.go"
readonly TMP_DIR="${SCRIPT_DIR}/.install-tmp"
readonly KATANA_VERSION="1.6.1"
readonly HTTPX_VERSION="1.9.0"
readonly DALFOX_VERSION="2.13.0"
readonly ACTIVATE_LINE="source ${SCRIPT_DIR}/activate-env.sh  # recon.sh"

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
log()  { echo -e "\033[1;34m[install]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[install]\033[0m $*"; }
warn() { echo -e "\033[1;33m[install]\033[0m $*"; }
die()  { echo -e "\033[1;31m[install]\033[0m $*" >&2; exit 1; }

# -----------------------------------------------------------------------------
# Verifica se está rodando no Kali Linux
# -----------------------------------------------------------------------------
check_kali() {
    if [[ ! -f /etc/os-release ]]; then
        die "Sistema não suportado. Este instalador é exclusivo para Kali Linux."
    fi
    # shellcheck source=/dev/null
    source /etc/os-release
    if [[ "${ID:-}" != "kali" && "${ID_LIKE:-}" != *"debian"* ]]; then
        warn "AVISO: Sistema detectado: ${PRETTY_NAME:-desconhecido}"
        warn "Este script foi feito para Kali Linux. Continuando mesmo assim..."
    else
        ok "Kali Linux detectado: ${PRETTY_NAME:-Kali}"
    fi
}

# -----------------------------------------------------------------------------
# Verifica privilégios (apt precisa de root)
# -----------------------------------------------------------------------------
check_privileges() {
    if [[ "${EUID}" -ne 0 ]]; then
        if command -v sudo &>/dev/null; then
            log "Reexecutando com sudo..."
            exec sudo bash "${SCRIPT_DIR}/install.sh" "$@"
        fi
        die "Execute como root ou com sudo: sudo ./install.sh"
    fi
}

# -----------------------------------------------------------------------------
# Instala pacote apt se existir no repositório (não falha se ausente)
# -----------------------------------------------------------------------------
apt_install_if_available() {
    local pkg="$1"
    if apt-cache show "${pkg}" &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkg}" &>/dev/null && \
            ok "  apt: ${pkg}" || warn "  apt falhou: ${pkg}"
    else
        warn "  apt não tem: ${pkg} (instalado depois via binário/go)"
    fi
}

# -----------------------------------------------------------------------------
# Pacotes apt base do Kali (sem httpx/subfinder/nuclei — não estão em todo Kali)
# -----------------------------------------------------------------------------
install_apt_packages() {
    log "Atualizando repositórios apt do Kali..."
    apt-get update -qq

    log "Instalando pacotes base..."
    local base_pkgs=(
        bash curl wget unzip tar git ca-certificates
        jq golang-go python3 python3-venv python3-pip
    )

    DEBIAN_FRONTEND=noninteractive apt-get install -y "${base_pkgs[@]}"

    # Opcionais: instala via apt só se existir no repositório local
    log "Verificando pacotes opcionais no apt..."
    apt_install_if_available subfinder
    apt_install_if_available httpx
    apt_install_if_available nuclei

    ok "Pacotes apt instalados."
}

# -----------------------------------------------------------------------------
# Configura Go para instalação local em tools/bin
# -----------------------------------------------------------------------------
setup_go_env() {
    export GOPATH="${GO_PATH}"
    export GOBIN="${TOOLS_BIN}"
    export PATH="${TOOLS_BIN}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}

# -----------------------------------------------------------------------------
# Baixa binário de release do GitHub (ProjectDiscovery e similares)
# Argumentos: repositório nome_binário [tag_fixa]
# -----------------------------------------------------------------------------
install_github_binary() {
    local repo="$1"
    local binary="$2"
    local fixed_tag="${3:-}"
    local tag ver url zip dest="${TOOLS_BIN}/${binary}"

    [[ -x "${dest}" ]] && { ok "${binary} já instalado."; return 0; }

    log "Baixando ${binary} (${repo})..."

    if [[ -n "${fixed_tag}" ]]; then
        tag="${fixed_tag}"
    else
        tag="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" \
            | grep '"tag_name"' | head -1 | cut -d'"' -f4)"
    fi

    ver="${tag#v}"

    # Padrões de nome usados nos releases ProjectDiscovery
    local urls=(
        "https://github.com/${repo}/releases/download/${tag}/${binary}_${ver}_linux_amd64.zip"
        "https://github.com/${repo}/releases/download/${tag}/${binary}_${ver}_linux_amd64.zip"
        "https://github.com/${repo}/releases/download/${tag}/${binary}-linux-amd64.zip"
        "https://github.com/${repo}/releases/download/${tag}/${binary}_linux_amd64.zip"
    )

    local zip="${TMP_DIR}/${binary}.zip"
    local downloaded=false

    for url in "${urls[@]}"; do
        if curl -fsSL --connect-timeout 30 -o "${zip}" "${url}" 2>/dev/null && [[ -s "${zip}" ]]; then
            downloaded=true
            break
        fi
    done

    if [[ "${downloaded}" != "true" ]]; then
        warn "Download de ${binary} falhou — tentando go install..."
        go install -v "${4:-}" 2>/dev/null && { ok "${binary} via go install."; return 0; }
        warn "Não foi possível instalar ${binary}"
        return 1
    fi

    unzip -qo "${zip}" -d "${TMP_DIR}/${binary}_extract"
    # Binário pode estar na raiz ou em subpasta
    local found
    found="$(find "${TMP_DIR}/${binary}_extract" -name "${binary}" -type f | head -1)"
    [[ -z "${found}" ]] && found="$(find "${TMP_DIR}/${binary}_extract" -type f -perm /111 | head -1)"

    install -m 755 "${found}" "${dest}"
    ok "${binary} instalado em ${dest}"
}

# -----------------------------------------------------------------------------
# Estrutura de diretórios do projeto
# -----------------------------------------------------------------------------
create_project_dirs() {
    log "Criando estrutura de diretórios..."
    mkdir -p "${TOOLS_BIN}" "${VENV_DIR}" "${GF_PATTERNS}" "${GO_PATH}" "${TMP_DIR}"
    mkdir -p "${SCRIPT_DIR}/config" "${SCRIPT_DIR}/checkpoints" "${SCRIPT_DIR}/logs"
    mkdir -p "${SCRIPT_DIR}/reports/json" "${SCRIPT_DIR}/reports/csv"
    mkdir -p "${SCRIPT_DIR}/workflows"
    mkdir -p "${SCRIPT_DIR}/output/subfinder"
    mkdir -p "${SCRIPT_DIR}/output/wayback"
    mkdir -p "${SCRIPT_DIR}/output/katana"
    mkdir -p "${SCRIPT_DIR}/output/hakrawler"
    mkdir -p "${SCRIPT_DIR}/output/httpx"
    mkdir -p "${SCRIPT_DIR}/output/uro"
    mkdir -p "${SCRIPT_DIR}/output/gf"
    mkdir -p "${SCRIPT_DIR}/output/dalfox"
    mkdir -p "${SCRIPT_DIR}/output/nuclei"
    mkdir -p "${SCRIPT_DIR}/output/consolidated"
    ok "Diretórios criados."
}

# -----------------------------------------------------------------------------
# Cria arquivos do projeto se não existirem (instalação mínima só com install.sh)
# -----------------------------------------------------------------------------
bootstrap_project_files() {
    log "Verificando arquivos do projeto..."

    # requirements.txt
    if [[ ! -f "${SCRIPT_DIR}/requirements.txt" ]]; then
        cat > "${SCRIPT_DIR}/requirements.txt" <<'EOF'
uro>=1.0.2
EOF
        ok "  criado: requirements.txt"
    fi

    # activate-env.sh
    if [[ ! -f "${SCRIPT_DIR}/activate-env.sh" ]]; then
        cat > "${SCRIPT_DIR}/activate-env.sh" <<'ACTIVATE_EOF'
#!/usr/bin/env bash
_RECON_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export RECON_HOME="${_RECON_ROOT}"
export PATH="${_RECON_ROOT}/tools/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
if [[ -f "${_RECON_ROOT}/venv/bin/activate" ]]; then
    source "${_RECON_ROOT}/venv/bin/activate"
fi
export GOPATH="${_RECON_ROOT}/.go"
export GOBIN="${_RECON_ROOT}/tools/bin"
if [[ -d "${_RECON_ROOT}/.gf-home" ]]; then
    export HOME="${_RECON_ROOT}/.gf-home"
fi
unset _RECON_ROOT
ACTIVATE_EOF
        chmod +x "${SCRIPT_DIR}/activate-env.sh"
        ok "  criado: activate-env.sh"
    fi

    # dominios.txt.example
    if [[ ! -f "${SCRIPT_DIR}/dominios.txt.example" ]]; then
        cat > "${SCRIPT_DIR}/dominios.txt.example" <<'EOF'
empresa.com
api.empresa.com
portal.empresa.com
EOF
        ok "  criado: dominios.txt.example"
    fi

    # scope.txt
    if [[ ! -f "${SCRIPT_DIR}/scope.txt" ]]; then
        cat > "${SCRIPT_DIR}/scope.txt" <<'EOF'
# Allowlist de escopo autorizado
empresa.com
*.empresa.com
EOF
        ok "  criado: scope.txt"
    fi

    # config/settings.conf
    if [[ ! -f "${SCRIPT_DIR}/config/settings.conf" ]]; then
        mkdir -p "${SCRIPT_DIR}/config"
        cat > "${SCRIPT_DIR}/config/settings.conf" <<'EOF'
THREADS=50
RATE_LIMIT=50
KATANA_DEPTH=5
HAKRAWLER_DEPTH=3
HTTP_TIMEOUT=10
NUCLEI_SEVERITY=low,medium,high,critical
SLEEP_BETWEEN_STAGES=5
SCOPE_FILE=scope.txt
OUTPUT_BASE=output
EOF
        ok "  criado: config/settings.conf"
    fi

    ok "Arquivos do projeto OK."
}

# -----------------------------------------------------------------------------
# Python venv — uro
# -----------------------------------------------------------------------------
install_python_venv() {
    log "Criando venv Python em ${VENV_DIR}..."

    if [[ ! -f "${VENV_DIR}/bin/activate" ]]; then
        python3 -m venv "${VENV_DIR}"
    fi

    # shellcheck source=/dev/null
    source "${VENV_DIR}/bin/activate"
    pip install --quiet --upgrade pip wheel

    if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
        pip install --quiet -r "${SCRIPT_DIR}/requirements.txt" || \
            pip install --quiet uro
    else
        pip install --quiet uro
    fi

    deactivate 2>/dev/null || true

    # Remove httpx Python do venv (conflita com ProjectDiscovery httpx)
    if [[ -f "${VENV_DIR}/bin/httpx" ]]; then
        if ! "${VENV_DIR}/bin/httpx" -h 2>&1 | grep -qE '\-l,|\-list'; then
            rm -f "${VENV_DIR}/bin/httpx"
            ok "Removido httpx Python conflitante do venv."
        fi
    fi

    if [[ ! -f "${VENV_DIR}/bin/uro" ]]; then
        warn "uro não encontrado no venv — tentando pip3 global..."
        pip3 install --quiet uro --break-system-packages 2>/dev/null || \
            pip3 install --quiet uro
        if command -v uro &>/dev/null; then
            ln -sf "$(command -v uro)" "${TOOLS_BIN}/uro"
        else
            warn "Falha ao instalar uro"
            return 1
        fi
    else
        ln -sf "${VENV_DIR}/bin/uro" "${TOOLS_BIN}/uro"
    fi

    ok "uro instalado: $(command -v uro 2>/dev/null || echo 'verificar PATH')"
}

# Verifica se binário é ProjectDiscovery (não httpx Python nem link errado)
is_pd_binary() {
    local binary="$1"
    [[ -x "${binary}" ]] || return 1
    "${binary}" -h 2>&1 | grep -qE '\-l,|\-list'
}

# Remove binários incorretos de tools/bin
sanitize_tools_bin() {
    # httpx: conflito frequente com pacote Python
    if [[ -e "${TOOLS_BIN}/httpx" ]] && ! is_pd_binary "${TOOLS_BIN}/httpx" 2>/dev/null; then
        warn "Removendo httpx Python/incorreto de tools/bin"
        rm -f "${TOOLS_BIN}/httpx"
    fi
}

# -----------------------------------------------------------------------------
# httpx ProjectDiscovery — SEMPRE via binário (evita conflito com httpx Python)
# -----------------------------------------------------------------------------
install_httpx_binary() {
    local dest="${TOOLS_BIN}/httpx"

    if is_pd_binary "${dest}"; then
        ok "httpx já correto: ${dest}"
        return 0
    fi

    rm -f "${dest}"
    log "Baixando httpx ProjectDiscovery v${HTTPX_VERSION}..."
    install_github_binary "projectdiscovery/httpx" "httpx" "v${HTTPX_VERSION}" \
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"

    if is_pd_binary "${dest}"; then
        ok "httpx: $("${dest}" -version 2>&1 | head -1)"
        return 0
    fi

    warn "Falha ao instalar httpx ProjectDiscovery"
    return 1
}

# -----------------------------------------------------------------------------
# ProjectDiscovery: subfinder, nuclei → tools/bin (httpx separado)
# -----------------------------------------------------------------------------
install_projectdiscovery_tools() {
    log "Instalando subfinder, httpx e nuclei em ${TOOLS_BIN}..."
    setup_go_env
    sanitize_tools_bin

    rm -rf "${GO_PATH}/pkg/mod/github.com/projectdiscovery" 2>/dev/null || true

    # httpx SEMPRE por binário — nunca linkar do PATH (conflito Python)
    install_httpx_binary

    local pd_tools=(
        "subfinder|projectdiscovery/subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "nuclei|projectdiscovery/nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    )

    local entry binary repo gomod
    for entry in "${pd_tools[@]}"; do
        IFS='|' read -r binary repo gomod <<< "${entry}"

        if [[ "${binary}" == "subfinder" ]] && [[ -x "${TOOLS_BIN}/${binary}" ]]; then
            ok "${binary} já em ${TOOLS_BIN}/${binary}"
            continue
        fi
        if [[ "${binary}" == "nuclei" ]] && [[ -x "${TOOLS_BIN}/${binary}" ]]; then
            ok "${binary} já em ${TOOLS_BIN}/${binary}"
            continue
        fi
        rm -f "${TOOLS_BIN}/${binary}"

        log "  → instalando ${binary}..."
        if go install -v "${gomod}" 2>/dev/null && is_pd_binary "${TOOLS_BIN}/${binary}"; then
            ok "${binary} via go install."
        elif install_github_binary "${repo}" "${binary}" "" "${gomod}"; then
            ok "${binary} via binário GitHub."
        else
            warn "Falha ao instalar ${binary}"
        fi
    done

    ok "Ferramentas ProjectDiscovery processadas."
}

# -----------------------------------------------------------------------------
# Ferramentas Go — instaladas localmente em tools/bin
# -----------------------------------------------------------------------------
install_go_tools() {
    log "Instalando waybackurls, hakrawler e gf em ${TOOLS_BIN}..."
    setup_go_env

    local modules=(
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/hakluke/hakrawler@latest"
        "github.com/tomnomnom/gf@latest"
    )

    for mod in "${modules[@]}"; do
        log "  → go install ${mod}"
        go install -v "${mod}" 2>&1 | tail -1 || warn "Falha parcial: ${mod}"
    done

    ok "Ferramentas Go instaladas."
}

# -----------------------------------------------------------------------------
# Katana — binário oficial (evita problemas de cache Go)
# -----------------------------------------------------------------------------
install_katana() {
    setup_go_env
    install_github_binary "projectdiscovery/katana" "katana" "v${KATANA_VERSION}" \
        "github.com/projectdiscovery/katana/cmd/katana@latest"
}

# -----------------------------------------------------------------------------
# Dalfox v2 — compatível com recon.sh
# -----------------------------------------------------------------------------
install_dalfox() {
    local dest="${TOOLS_BIN}/dalfox"
    [[ -x "${dest}" ]] && { ok "dalfox já instalado."; return 0; }

    log "Baixando Dalfox v${DALFOX_VERSION}..."

    local urls=(
        "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-linux-amd64.tar.gz"
        "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox_linux_amd64.tar.gz"
    )
    local tgz="${TMP_DIR}/dalfox.tar.gz"
    local extract="${TMP_DIR}/dalfox_extract"
    local downloaded=false

    mkdir -p "${extract}"

    for url in "${urls[@]}"; do
        if curl -fsSL --connect-timeout 30 -o "${tgz}" "${url}" 2>/dev/null && [[ -s "${tgz}" ]]; then
            downloaded=true
            break
        fi
    done

    if [[ "${downloaded}" == "true" ]]; then
        tar xzf "${tgz}" -C "${extract}"
        local found
        found="$(find "${extract}" -name 'dalfox' -type f | head -1)"
        [[ -z "${found}" ]] && found="$(find "${extract}" -type f -perm /111 | head -1)"
        if [[ -n "${found}" ]]; then
            install -m 755 "${found}" "${dest}"
            ok "Dalfox instalado: $("${dest}" version 2>&1 | head -1)"
            return 0
        fi
    fi

    warn "Download dalfox falhou — tentando go install v2..."
    setup_go_env
    if go install -v github.com/hahwul/dalfox/v2@latest 2>/dev/null && [[ -x "${TOOLS_BIN}/dalfox" ]]; then
        ok "Dalfox via go install."
        return 0
    fi

    warn "Não foi possível instalar dalfox"
    return 1
}

# -----------------------------------------------------------------------------
# GF patterns
# -----------------------------------------------------------------------------
install_gf_patterns() {
    log "Instalando GF patterns..."
    if [[ ! -d "${GF_PATTERNS}/.git" ]]; then
        git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns "${GF_PATTERNS}"
    fi

    mkdir -p "${SCRIPT_DIR}/.gf-home/.gf"
    cp -rn "${GF_PATTERNS}/." "${SCRIPT_DIR}/.gf-home/.gf/" 2>/dev/null || true
    ok "GF patterns instalados."
}

# -----------------------------------------------------------------------------
# Templates Nuclei
# -----------------------------------------------------------------------------
update_nuclei_templates() {
    log "Atualizando templates Nuclei..."
    setup_go_env
    if command -v nuclei &>/dev/null; then
        nuclei -update-templates -silent 2>/dev/null || warn "Atualização de templates falhou (não crítico)."
    else
        warn "nuclei não encontrado — pulando templates."
    fi
    ok "Templates Nuclei OK."
}

# -----------------------------------------------------------------------------
# Permissões e arquivos de configuração
# -----------------------------------------------------------------------------
configure_project() {
    log "Configurando projeto..."

    local scripts=(install.sh)
    [[ -f "${SCRIPT_DIR}/recon.sh" ]]         && scripts+=(recon.sh)
    [[ -f "${SCRIPT_DIR}/activate-env.sh" ]]  && scripts+=(activate-env.sh)
    chmod +x "${scripts[@]/#/${SCRIPT_DIR}/}" 2>/dev/null || true

    for f in recon.sh activate-env.sh install.sh; do
        [[ -f "${SCRIPT_DIR}/${f}" ]] && sed -i 's/\r$//' "${SCRIPT_DIR}/${f}" 2>/dev/null || true
    done
    [[ -f "${SCRIPT_DIR}/config/settings.conf" ]] && \
        sed -i 's/\r$//' "${SCRIPT_DIR}/config/settings.conf" 2>/dev/null || true

    if [[ ! -f "${SCRIPT_DIR}/dominios.txt" ]]; then
        cp "${SCRIPT_DIR}/dominios.txt.example" "${SCRIPT_DIR}/dominios.txt" 2>/dev/null || \
            echo "empresa.com" > "${SCRIPT_DIR}/dominios.txt"
    fi

    ok "Projeto configurado."
}

# -----------------------------------------------------------------------------
# Registra ambiente no shell do Kali (.zshrc e .bashrc)
# -----------------------------------------------------------------------------
register_shell_env() {
    log "Registrando ambiente no shell do Kali..."

    local rc_files=()
    [[ -f /root/.zshrc ]]    && rc_files+=("/root/.zshrc")
    [[ -f /root/.bashrc ]]    && rc_files+=("/root/.bashrc")
    [[ -f "${SUDO_USER:+$(eval echo ~${SUDO_USER})/.zshrc}" ]] && \
        rc_files+=("$(eval echo ~${SUDO_USER})/.zshrc")
    [[ -n "${SUDO_USER:-}" && -f "$(eval echo ~${SUDO_USER})/.bashrc" ]] && \
        rc_files+=("$(eval echo ~${SUDO_USER})/.bashrc")

    local rc
    for rc in "${rc_files[@]}"; do
        if [[ -f "${rc}" ]] && ! grep -qF "activate-env.sh  # recon.sh" "${rc}" 2>/dev/null; then
            echo "" >> "${rc}"
            echo "${ACTIVATE_LINE}" >> "${rc}"
            ok "Ambiente adicionado em: ${rc}"
        fi
    done
}

# -----------------------------------------------------------------------------
# Reinstala ferramentas que falharam na primeira tentativa
# -----------------------------------------------------------------------------
fix_missing_tools() {
    setup_go_env
    export PATH="${TOOLS_BIN}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    if ! is_pd_binary "${TOOLS_BIN}/httpx" 2>/dev/null; then
        warn "httpx incorreto — reinstalando ProjectDiscovery..."
        install_httpx_binary || true
    fi

    if ! command -v uro &>/dev/null; then
        warn "uro ausente — reinstalando..."
        install_python_venv || true
    fi

    if ! command -v dalfox &>/dev/null; then
        warn "dalfox ausente — reinstalando..."
        install_dalfox || true
    fi
}

# -----------------------------------------------------------------------------
# Verificação final de todas as dependências
# -----------------------------------------------------------------------------
verify_installation() {
    log "Verificando instalação..."

    export PATH="${TOOLS_BIN}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    # shellcheck source=/dev/null
    [[ -f "${VENV_DIR}/bin/activate" ]] && source "${VENV_DIR}/bin/activate"
    # tools/bin após venv (prioridade sobre httpx Python)
    export PATH="${TOOLS_BIN}:${PATH}"
    [[ -d "${SCRIPT_DIR}/.gf-home" ]] && export HOME="${SCRIPT_DIR}/.gf-home"

    local required=(subfinder httpx waybackurls katana hakrawler uro gf dalfox nuclei jq)
    local missing=()

    echo ""
    echo "╔══════════════════════════════════════════╗"
    echo "║       VERIFICAÇÃO DE DEPENDÊNCIAS         ║"
    echo "╠══════════════════════════════════════════╣"
    for tool in "${required[@]}"; do
        local tool_path=""
        if [[ "${tool}" == "httpx" ]]; then
            if is_pd_binary "${TOOLS_BIN}/httpx"; then
                tool_path="${TOOLS_BIN}/httpx"
            fi
        else
         
