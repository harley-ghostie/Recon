#!/usr/bin/env bash
# =============================================================================
# recon.sh - Pipeline de Reconhecimento Web Autorizado (Kali Linux)
# =============================================================================
# Uso:
#   ./install.sh                  # instalar dependências (primeira vez)
#   ./recon.sh -l dominios.txt    # executar pipeline
#   ./recon.sh -l dominios.txt --resume
#
# AVISO LEGAL: Utilize exclusivamente em alvos com autorização explícita.
# =============================================================================

set -uo pipefail

# -----------------------------------------------------------------------------
# Variáveis globais
# -----------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.1.0"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# Ambiente isolado Kali (install.sh): tools/bin + venv + GF
if [[ -f "${SCRIPT_DIR}/venv/bin/activate" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/venv/bin/activate"
fi
# tools/bin DEPOIS do venv para ter prioridade sobre httpx Python
if [[ -d "${SCRIPT_DIR}/tools/bin" ]]; then
    export PATH="${SCRIPT_DIR}/tools/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
fi
if [[ -d "${SCRIPT_DIR}/.gf-home" ]]; then
    export HOME="${SCRIPT_DIR}/.gf-home"
fi
export RECON_HOME="${SCRIPT_DIR}"
# httpx ProjectDiscovery (não confundir com httpx Python do pip)
export HTTPX_BIN="${SCRIPT_DIR}/tools/bin/httpx"

# Diretórios do projeto
CONFIG_DIR="${SCRIPT_DIR}/config"
CHECKPOINT_DIR="${SCRIPT_DIR}/checkpoints"
LOG_DIR="${SCRIPT_DIR}/logs"
REPORT_DIR="${SCRIPT_DIR}/reports"
WORKFLOW_DIR="${SCRIPT_DIR}/workflows"
OUTPUT_DIR="${SCRIPT_DIR}/output"

# Subdiretórios de output
OUTPUT_SUBFINDER="${OUTPUT_DIR}/subfinder"
OUTPUT_WAYBACK="${OUTPUT_DIR}/wayback"
OUTPUT_KATANA="${OUTPUT_DIR}/katana"
OUTPUT_HAKRAWLER="${OUTPUT_DIR}/hakrawler"
OUTPUT_HTTPX="${OUTPUT_DIR}/httpx"
OUTPUT_URO="${OUTPUT_DIR}/uro"
OUTPUT_GF="${OUTPUT_DIR}/gf"
OUTPUT_DALFOX="${OUTPUT_DIR}/dalfox"
OUTPUT_NUCLEI="${OUTPUT_DIR}/nuclei"
OUTPUT_CONSOLIDATED="${OUTPUT_DIR}/consolidated"
REPORT_JSON_DIR="${REPORT_DIR}/json"
REPORT_CSV_DIR="${REPORT_DIR}/csv"

# Arquivos de configuração e escopo
CONFIG_FILE="${CONFIG_DIR}/settings.conf"
SCOPE_FILE="${SCRIPT_DIR}/scope.txt"

# Flags de execução
DOMAIN_LIST_FILE=""
RESUME_MODE=false
PIPELINE_START_TIME=0

# Contadores de métricas
METRIC_SUBDOMAINS=0
METRIC_ACTIVE_HOSTS=0
METRIC_UNIQUE_URLS=0
METRIC_URLS_200=0
METRIC_VULN_CANDIDATES=0
METRIC_NUCLEI_FINDINGS=0
METRIC_DALFOX_FINDINGS=0

# Arquivo de log principal
LOG_FILE="${LOG_DIR}/recon.log"

# Diretório temporário seguro (limpo ao finalizar)
TEMP_DIR=""

# Lista de dependências obrigatórias
readonly REQUIRED_TOOLS=(
    subfinder httpx waybackurls katana hakrawler uro gf dalfox nuclei jq
)

# Estágios do pipeline (ordem de execução)
readonly PIPELINE_STAGES=(
    subfinder
    httpx_hosts
    waybackurls
    katana
    hakrawler
    consolidate
    uro
    httpx_urls
    gf_patterns
    dalfox
    nuclei
    reports
)

# =============================================================================
# FUNÇÕES DE UTILIDADE
# =============================================================================

# Exibe mensagem de uso e encerra
usage() {
    cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} - Reconhecimento Web Autorizado

Uso:
  ${SCRIPT_NAME} -l <arquivo_dominios> [--resume]

Opções:
  -l, --list <arquivo>   Arquivo com lista de domínios (um por linha)
  --resume               Retomar execução a partir do último checkpoint
  -h, --help             Exibir esta ajuda

Exemplo:
  ${SCRIPT_NAME} -l dominios.txt
  ${SCRIPT_NAME} -l dominios.txt --resume

Estrutura esperada:
  config/settings.conf   Configurações do pipeline
  scope.txt              Allowlist de escopo autorizado
  workflows/             Workflow Nuclei customizado

EOF
    exit "${1:-0}"
}

# Registra mensagem no log e opcionalmente no stdout
# Argumentos: nível mensagem [exibir_console]
log_msg() {
    local level="$1"
    local message="$2"
    local to_console="${3:-true}"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    local line="[${timestamp}] [${level}] ${message}"
    echo "${line}" >> "${LOG_FILE}"

    if [[ "${to_console}" == "true" ]]; then
        case "${level}" in
            ERROR)   echo -e "\033[0;31m${line}\033[0m" >&2 ;;
            WARN)    echo -e "\033[0;33m${line}\033[0m" ;;
            SUCCESS) echo -e "\033[0;32m${line}\033[0m" ;;
            *)       echo "${line}" ;;
        esac
    fi
}

# Exibe barra de progresso simples no terminal
# Argumentos: atual total [largura] [prefixo]
show_progress() {
    local current="$1"
    local total="$2"
    local width="${3:-40}"
    local prefix="${4:-Progresso}"

    if [[ "${total}" -le 0 ]]; then
        return 0
    fi

    local percent=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))

    local bar=""
    local i
    for ((i = 0; i < filled; i++)); do bar+="#"; done
    for ((i = 0; i < empty; i++)); do bar+="-"; done

    printf "\r%s [%s] %3d%% (%d/%d)" "${prefix}" "${bar}" "${percent}" "${current}" "${total}"

    if [[ "${current}" -ge "${total}" ]]; then
        echo ""
    fi
}

# Formata segundos em HH:MM:SS
format_duration() {
    local seconds="$1"
    local h=$((seconds / 3600))
    local m=$(((seconds % 3600) / 60))
    local s=$((seconds % 60))
    printf '%02d:%02d:%02d' "${h}" "${m}" "${s}"
}

# Conta linhas não vazias de um arquivo
count_lines() {
    local file="$1"
    if [[ -f "${file}" && -s "${file}" ]]; then
        grep -cve '^[[:space:]]*$' "${file}" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# Cria diretório se não existir
ensure_dir() {
    local dir="$1"
    if [[ ! -d "${dir}" ]]; then
        mkdir -p "${dir}"
    fi
}

# =============================================================================
# INICIALIZAÇÃO E CONFIGURAÇÃO
# =============================================================================

# Processa argumentos da linha de comando
parse_args() {
    if [[ $# -eq 0 ]]; then
        usage 1
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -l|--list)
                [[ $# -lt 2 ]] && { log_msg ERROR "Opção -l requer um arquivo."; usage 1; }
                DOMAIN_LIST_FILE="$2"
                shift 2
                ;;
            --resume)
                RESUME_MODE=true
                shift
                ;;
            -h|--help)
                usage 0
                ;;
            *)
                log_msg ERROR "Argumento desconhecido: $1"
                usage 1
                ;;
        esac
    done

    if [[ -z "${DOMAIN_LIST_FILE}" ]]; then
        log_msg ERROR "Arquivo de domínios não informado. Use -l <arquivo>."
        usage 1
    fi

    if [[ ! -f "${DOMAIN_LIST_FILE}" ]]; then
        log_msg ERROR "Arquivo de domínios não encontrado: ${DOMAIN_LIST_FILE}"
        exit 1
    fi
}

# Carrega configurações do arquivo externo
load_config() {
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_msg ERROR "Arquivo de configuração não encontrado: ${CONFIG_FILE}"
        exit 1
    fi

    # shellcheck source=/dev/null
    source "${CONFIG_FILE}"

    # Valores padrão caso ausentes no config
    THREADS="${THREADS:-50}"
    RATE_LIMIT="${RATE_LIMIT:-50}"
    KATANA_DEPTH="${KATANA_DEPTH:-5}"
    HAKRAWLER_DEPTH="${HAKRAWLER_DEPTH:-3}"
    HTTP_TIMEOUT="${HTTP_TIMEOUT:-10}"
    NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-low,medium,high,critical}"
    SLEEP_BETWEEN_STAGES="${SLEEP_BETWEEN_STAGES:-5}"

    if [[ -n "${SCOPE_FILE:-}" && "${SCOPE_FILE}" != /* ]]; then
        SCOPE_FILE="${SCRIPT_DIR}/${SCOPE_FILE}"
    fi

    log_msg INFO "Configuração carregada: THREADS=${THREADS}, RATE_LIMIT=${RATE_LIMIT}"
}

# Cria toda a estrutura de diretórios do projeto
init_directories() {
    local dirs=(
        "${CONFIG_DIR}"
        "${CHECKPOINT_DIR}"
        "${LOG_DIR}"
        "${REPORT_DIR}"
        "${REPORT_JSON_DIR}"
        "${REPORT_CSV_DIR}"
        "${WORKFLOW_DIR}"
        "${OUTPUT_SUBFINDER}"
        "${OUTPUT_WAYBACK}"
        "${OUTPUT_KATANA}"
        "${OUTPUT_HAKRAWLER}"
        "${OUTPUT_HTTPX}"
        "${OUTPUT_URO}"
        "${OUTPUT_GF}"
        "${OUTPUT_DALFOX}"
        "${OUTPUT_NUCLEI}"
        "${OUTPUT_CONSOLIDATED}"
    )

    for dir in "${dirs[@]}"; do
        ensure_dir "${dir}"
    done

    TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/recon.XXXXXX")"
    log_msg INFO "Diretório temporário: ${TEMP_DIR}"
}

# Valida presença de todas as dependências obrigatórias
check_dependencies() {
    local missing=()
    local tool

    log_msg INFO "Validando dependências obrigatórias..."

    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "${tool}" &>/dev/null; then
            missing+=("${tool}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_msg ERROR "Ferramentas ausentes: ${missing[*]}"
        log_msg ERROR "Execute o instalador: sudo ${SCRIPT_DIR}/install.sh"
        exit 1
    fi

    log_msg SUCCESS "Todas as dependências obrigatórias estão disponíveis."
    ensure_pd_httpx || exit 1
}

# Garante uso do httpx do ProjectDiscovery (não o pacote Python homônimo)
ensure_pd_httpx() {
    local httpx_bin="${HTTPX_BIN}"
    local httpx_path

    if [[ -x "${httpx_bin}" ]]; then
        if "${httpx_bin}" -h 2>&1 | grep -qE '\-l,|\-list'; then
            log_msg INFO "httpx OK: ${httpx_bin}"
            return 0
        fi
    fi

    httpx_path="$(command -v httpx 2>/dev/null || true)"
    if [[ -n "${httpx_path}" ]] && httpx -h 2>&1 | grep -qE '\-l,|\-list'; then
        HTTPX_BIN="${httpx_path}"
        export HTTPX_BIN
        log_msg INFO "httpx OK: ${HTTPX_BIN}"
        return 0
    fi

    log_msg ERROR "httpx ProjectDiscovery não encontrado."
    log_msg ERROR "O venv instala httpx Python (errado). Use: ${SCRIPT_DIR}/tools/bin/httpx"
    log_msg ERROR "Execute: sudo ${SCRIPT_DIR}/install.sh"
    return 1
}

# Normaliza lista de hosts (remove CRLF, comentários, paths, portas)
normalize_hosts_input() {
    local in_file="$1"
    local out_file="$2"
    sed 's/\r$//' "${in_file}" \
        | grep -v '^[[:space:]]*#' \
        | grep -v '^[[:space:]]*$' \
        | sed -E 's|^https?://||' \
        | cut -d'/' -f1 \
        | cut -d':' -f1 \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u > "${out_file}"
}

# Extrai URLs de saída JSONL do httpx
parse_httpx_jsonl_urls() {
    local json_file="$1"
    local out_txt="$2"
    : > "${out_txt}"

    [[ ! -s "${json_file}" ]] && return 0

    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ -z "${line}" ]] && continue
        echo "${line}" | jq -r '.url // .input // empty' 2>/dev/null
    done < "${json_file}" | grep -v '^[[:space:]]*$' | sort -u > "${out_txt}"
}

# Executa httpx com tratamento de exit code (1 = sem resultados, não é erro fatal)
run_httpx() {
    local input_list="$1"
    local output_json="$2"
    shift 2
    local extra_args=("$@")
    local httpx_exit=0
    local httpx_cmd="${HTTPX_BIN:-httpx}"

    if [[ ! -x "${httpx_cmd}" ]] && ! command -v "${httpx_cmd}" &>/dev/null; then
        log_msg ERROR "httpx não encontrado: ${httpx_cmd}"
        return 1
    fi

    if [[ ! -s "${input_list}" ]]; then
        log_msg WARN "Lista vazia para httpx: ${input_list}"
        : > "${output_json}"
        return 0
    fi

    "${httpx_cmd}" \
        -l "${input_list}" \
        -silent \
        -no-color \
        -status-code \
        -follow-redirects \
        -timeout "${HTTP_TIMEOUT}" \
        -c "${THREADS}" \
        -rl "${RATE_LIMIT}" \
        -json \
        -o "${output_json}" \
        "${extra_args[@]}" \
        2>> "${LOG_FILE}" || httpx_exit=$?

    # 0 = sucesso | 1 = sem resultados (comum) | >1 = erro real
    if [[ "${httpx_exit}" -gt 1 ]]; then
        log_msg ERROR "httpx falhou (exit ${httpx_exit}). Verifique logs/recon.log"
        return 1
    fi

    [[ "${httpx_exit}" -eq 1 ]] && \
        log_msg WARN "httpx: nenhum host/URL respondeu (exit 1 — normal se alvos estiverem offline)."

    return 0
}

# =============================================================================
# CHECKPOINTS
# =============================================================================

# Retorna caminho do arquivo de checkpoint de um estágio
checkpoint_file() {
    local stage="$1"
    echo "${CHECKPOINT_DIR}/.${stage}.done"
}

# Marca estágio como concluído
mark_checkpoint() {
    local stage="$1"
    local cp_file
    cp_file="$(checkpoint_file "${stage}")"
    date '+%Y-%m-%d %H:%M:%S' > "${cp_file}"
    log_msg INFO "Checkpoint salvo: ${stage}"
}

# Verifica se estágio já foi concluído (modo resume)
is_stage_done() {
    local stage="$1"
    [[ -f "$(checkpoint_file "${stage}")" ]]
}

# Decide se deve pular estágio no modo resume
should_skip_stage() {
    local stage="$1"
    if [[ "${RESUME_MODE}" == "true" ]] && is_stage_done "${stage}"; then
        log_msg INFO "Estágio '${stage}' já concluído — pulando (resume)."
        return 0
    fi
    return 1
}

# Pausa configurável entre estágios
sleep_between_stages() {
    if [[ "${SLEEP_BETWEEN_STAGES}" -gt 0 ]]; then
        log_msg INFO "Aguardando ${SLEEP_BETWEEN_STAGES}s antes do próximo estágio..."
        sleep "${SLEEP_BETWEEN_STAGES}"
    fi
}

# =============================================================================
# ESCOPO (ALLOWLIST)
# =============================================================================

# Verifica se um host está dentro do escopo autorizado
# Suporta: domínio exato, subdomínio e wildcard (*.dominio.com)
is_in_scope() {
    local host="$1"
    local pattern

    if [[ ! -f "${SCOPE_FILE}" ]]; then
        log_msg WARN "Arquivo de escopo não encontrado: ${SCOPE_FILE} — aceitando todos os hosts."
        return 0
    fi

    while IFS= read -r pattern || [[ -n "${pattern}" ]]; do
        pattern="${pattern%%#*}"
        pattern="$(echo "${pattern}" | xargs)"
        [[ -z "${pattern}" ]] && continue

        # Wildcard: *.empresa.com
        if [[ "${pattern}" == \** ]]; then
            local suffix="${pattern#\*}"
            if [[ "${host}" == "${suffix#.}" || "${host}" == *"${suffix}" ]]; then
                return 0
            fi
        # Domínio exato ou subdomínio
        elif [[ "${host}" == "${pattern}" || "${host}" == *".${pattern}" ]]; then
            return 0
        fi
    done < "${SCOPE_FILE}"

    return 1
}

# Filtra arquivo de hosts mantendo apenas os que estão no escopo
filter_hosts_by_scope() {
    local input_file="$1"
    local output_file="$2"
    local host
    local total=0
    local kept=0
    local rejected=0

    : > "${output_file}"

    while IFS= read -r host || [[ -n "${host}" ]]; do
        host="$(echo "${host}" | xargs | sed 's|https\?://||' | cut -d'/' -f1)"
        [[ -z "${host}" ]] && continue
        total=$((total + 1))

        if is_in_scope "${host}"; then
            echo "${host}" >> "${output_file}"
            kept=$((kept + 1))
        else
            log_msg WARN "Host fora do escopo ignorado: ${host}" false
            rejected=$((rejected + 1))
        fi

        show_progress "${total}" "${total}" 40 "Validando escopo"
    done < "${input_file}"

    log_msg INFO "Escopo: ${kept} hosts aceitos, ${rejected} rejeitados."
}

# =============================================================================
# LEITURA DE DOMÍNIOS
# =============================================================================

# Lê e valida lista de domínios de entrada
read_domains() {
    local raw_file="${TEMP_DIR}/domains_raw.txt"
    local scoped_file="${OUTPUT_CONSOLIDATED}/domains_scoped.txt"

    grep -v '^[[:space:]]*#' "${DOMAIN_LIST_FILE}" | grep -v '^[[:space:]]*$' \
        | sed 's|https\?://||' | cut -d'/' -f1 | sort -u > "${raw_file}"

    filter_hosts_by_scope "${raw_file}" "${scoped_file}"

    local count
    count="$(count_lines "${scoped_file}")"
    if [[ "${count}" -eq 0 ]]; then
        log_msg ERROR "Nenhum domínio válido no escopo após filtragem."
        exit 1
    fi

    log_msg SUCCESS "Domínios no escopo: ${count}"
    cp "${scoped_file}" "${OUTPUT_CONSOLIDATED}/domains.txt"
}

# =============================================================================
# GERAÇÃO DO WORKFLOW NUCLEI
# =============================================================================

# Cria workflow Nuclei customizado se não existir
generate_nuclei_workflow() {
    local workflow_file="${WORKFLOW_DIR}/web-workflow.yaml"

    if [[ -f "${workflow_file}" ]]; then
        log_msg INFO "Workflow Nuclei existente: ${workflow_file}"
        return 0
    fi

    log_msg INFO "Gerando workflow Nuclei: ${workflow_file}"

    cat > "${workflow_file}" <<'EOF'
id: web-recon-workflow
info:
  name: Web Reconnaissance Workflow
  author: recon.sh
  description: Pipeline de varredura web - technologies, exposures, misconfigurations, CVEs e takeovers
  severity: info

workflows:
  - template: http/technologies/
    matchers: true
    subtemplates:
      - tags: tech

  - template: http/exposures/
    matchers: true
    subtemplates:
      - tags: exposure

  - template: http/misconfiguration/
    matchers: true
    subtemplates:
      - tags: misconfig

  - template: http/cves/
    matchers: true
    subtemplates:
      - tags: cve

  - template: http/takeovers/
    matchers: true
    subtemplates:
      - tags: takeover
EOF

    log_msg SUCCESS "Workflow Nuclei criado com sucesso."
}

# =============================================================================
# ESTÁGIOS DO PIPELINE
# =============================================================================

# Wrapper genérico para executar estágio com log de tempo e tratamento de erro
run_stage() {
    local stage_name="$1"
    local stage_func="$2"
    local stage_start
    local stage_end
    local stage_duration

    if should_skip_stage "${stage_name}"; then
        return 0
    fi

    log_msg INFO "========== Iniciando estágio: ${stage_name} =========="
    stage_start=$(date +%s)

    if "${stage_func}"; then
        stage_end=$(date +%s)
        stage_duration=$((stage_end - stage_start))
        mark_checkpoint "${stage_name}"
        log_msg SUCCESS "Estágio '${stage_name}' concluído em $(format_duration "${stage_duration}")."
        sleep_between_stages
        return 0
    else
        stage_end=$(date +%s)
        stage_duration=$((stage_end - stage_start))
        log_msg ERROR "Estágio '${stage_name}' falhou após $(format_duration "${stage_duration}"). Continuando pipeline..."
        sleep_between_stages
        return 0
    fi
}

# Estágio 1: Descoberta de subdomínios com Subfinder
stage_subfinder() {
    local domains="${OUTPUT_CONSOLIDATED}/domains.txt"
    local out_txt="${OUTPUT_SUBFINDER}/subdomains.txt"
    local out_json="${OUTPUT_SUBFINDER}/subdomains.json"
    local scoped="${OUTPUT_SUBFINDER}/subdomains_scoped.txt"

    subfinder \
        -dL "${domains}" \
        -all \
        -silent \
        -t "${THREADS}" \
        -json \
        -o "${out_json}" \
        2>> "${LOG_FILE}" || {
            log_msg ERROR "Subfinder retornou erro."
            return 1
        }

    # Extrai hosts do JSON (um objeto por linha) e filtra por escopo
    if [[ -f "${out_json}" && -s "${out_json}" ]]; then
        jq -r '.host // .Host // empty' "${out_json}" 2>/dev/null \
            | sort -u > "${TEMP_DIR}/subfinder_raw.txt" || true
    fi

    if [[ ! -s "${TEMP_DIR}/subfinder_raw.txt" ]]; then
        subfinder -dL "${domains}" -all -silent -t "${THREADS}" -o "${out_txt}" \
            2>> "${LOG_FILE}" || true
        cp "${out_txt}" "${TEMP_DIR}/subfinder_raw.txt" 2>/dev/null || : > "${TEMP_DIR}/subfinder_raw.txt"
    fi

    filter_hosts_by_scope "${TEMP_DIR}/subfinder_raw.txt" "${scoped}"
    cp "${scoped}" "${out_txt}"

    METRIC_SUBDOMAINS="$(count_lines "${out_txt}")"
    log_msg INFO "Subfinder: ${METRIC_SUBDOMAINS} subdomínios encontrados."

    # Copia JSON para reports
    if [[ -f "${out_json}" ]]; then
        cp "${out_json}" "${REPORT_JSON_DIR}/subfinder.json"
    fi

    [[ "${METRIC_SUBDOMAINS}" -gt 0 ]]
}

# Estágio 2: Validação de hosts ativos com httpx
stage_httpx_hosts() {
    local hosts_in="${OUTPUT_SUBFINDER}/subdomains.txt"
    local out_json="${OUTPUT_HTTPX}/hosts.json"
    local out_txt="${OUTPUT_HTTPX}/hosts_active.txt"
    local fallback_domains="${OUTPUT_CONSOLIDATED}/domains.txt"
    local normalized="${TEMP_DIR}/httpx_hosts_input.txt"

    if [[ ! -s "${hosts_in}" ]]; then
        log_msg WARN "Sem subdomínios — usando domínios raiz para httpx."
        hosts_in="${fallback_domains}"
    fi

    if [[ ! -s "${hosts_in}" ]]; then
        log_msg WARN "Nenhum host para httpx — pulando estágio."
        : > "${out_json}"
        : > "${out_txt}"
        METRIC_ACTIVE_HOSTS=0
        return 0
    fi

    normalize_hosts_input "${hosts_in}" "${normalized}"
    log_msg INFO "httpx: testando $(count_lines "${normalized}") hosts..."

    run_httpx "${normalized}" "${out_json}" -title -tech-detect || {
        log_msg ERROR "httpx (hosts) falhou."
        : > "${out_txt}"
        METRIC_ACTIVE_HOSTS=0
        return 0
    }

    parse_httpx_jsonl_urls "${out_json}" "${out_txt}"

    if [[ -s "${out_json}" ]]; then
        cp "${out_json}" "${REPORT_JSON_DIR}/httpx_hosts.json"
    fi

    METRIC_ACTIVE_HOSTS="$(count_lines "${out_txt}")"
    log_msg INFO "httpx (hosts): ${METRIC_ACTIVE_HOSTS} hosts ativos."

    [[ "${METRIC_ACTIVE_HOSTS}" -eq 0 ]] && \
        log_msg WARN "Nenhum host ativo — pipeline continuará com domínios raiz."

    return 0
}

# Estágio 3: Coleta de URLs históricas com Waybackurls
stage_waybackurls() {
    local domains="${OUTPUT_CONSOLIDATED}/domains.txt"
    local hosts="${OUTPUT_HTTPX}/hosts_active.txt"
    local out_file="${OUTPUT_WAYBACK}/urls.txt"
    local input_list="${TEMP_DIR}/wayback_input.txt"

    : > "${input_list}"
    cat "${domains}" >> "${input_list}" 2>/dev/null || true

    if [[ -s "${hosts}" ]]; then
        sed 's|https\?://||' "${hosts}" | cut -d'/' -f1 >> "${input_list}" 2>/dev/null || true
    fi

    sort -u "${input_list}" -o "${input_list}"
    : > "${out_file}"

    local domain total=0
    total="$(count_lines "${input_list}")"
    local current=0

    while IFS= read -r domain || [[ -n "${domain}" ]]; do
        [[ -z "${domain}" ]] && continue
        current=$((current + 1))
        waybackurls "${domain}" >> "${out_file}" 2>> "${LOG_FILE}" || \
            log_msg WARN "Waybackurls falhou para: ${domain}" false
        show_progress "${current}" "${total}" 40 "Waybackurls"
    done < "${input_list}"

    sort -u "${out_file}" -o "${out_file}"
    local count
    count="$(count_lines "${out_file}")"
    log_msg INFO "Waybackurls: ${count} URLs históricas coletadas."
    return 0
}

# Estágio 4: Crawling com Katana
stage_katana() {
    local hosts="${OUTPUT_HTTPX}/hosts_active.txt"
    local out_jsonl="${OUTPUT_KATANA}/katana.jsonl"
    local out_txt="${OUTPUT_KATANA}/urls.txt"

    if [[ ! -s "${hosts}" ]]; then
        log_msg WARN "Sem hosts ativos para Katana."
        : > "${out_txt}"
        return 0
    fi

    katana \
        -list "${hosts}" \
        -d "${KATANA_DEPTH}" \
        -silent \
        -jsonl \
        -c "${THREADS}" \
        -rl "${RATE_LIMIT}" \
        -timeout "${HTTP_TIMEOUT}" \
        -o "${out_jsonl}" \
        2>> "${LOG_FILE}" || {
            log_msg ERROR "Katana retornou erro."
            return 1
        }

    if [[ -f "${out_jsonl}" && -s "${out_jsonl}" ]]; then
        jq -r '.request.endpoint // .url // empty' "${out_jsonl}" 2>/dev/null \
            | sort -u > "${out_txt}" || : > "${out_txt}"
        cp "${out_jsonl}" "${REPORT_JSON_DIR}/katana.jsonl"
    else
        : > "${out_txt}"
    fi

    local count
    count="$(count_lines "${out_txt}")"
    log_msg INFO "Katana: ${count} URLs descobertas."
    return 0
}

# Estágio 5: Crawling complementar com Hakrawler
stage_hakrawler() {
    local hosts="${OUTPUT_HTTPX}/hosts_active.txt"
    local out_file="${OUTPUT_HAKRAWLER}/urls.txt"

    if [[ ! -s "${hosts}" ]]; then
        log_msg WARN "Sem hosts ativos para Hakrawler."
        : > "${out_file}"
        return 0
    fi

  # Hakrawler lê URLs via stdin (hosts já podem conter esquema http/https)
    {
        while IFS= read -r host || [[ -n "${host}" ]]; do
            [[ -z "${host}" ]] && continue
            if [[ "${host}" =~ ^https?:// ]]; then
                echo "${host}"
            else
                echo "https://${host}"
            fi
        done < "${hosts}"
    } | hakrawler \
        -depth "${HAKRAWLER_DEPTH}" \
        -plain \
        -timeout "${HTTP_TIMEOUT}" \
        2>> "${LOG_FILE}" | sort -u > "${out_file}" || {
            log_msg ERROR "Hakrawler retornou erro."
            : > "${out_file}"
            return 1
        }

    local count
    count="$(count_lines "${out_file}")"
    log_msg INFO "Hakrawler: ${count} URLs descobertas."
    return 0
}

# Estágio 6: Consolidação de todas as URLs coletadas
stage_consolidate() {
    local out_all="${OUTPUT_CONSOLIDATED}/all_urls.txt"
    local sources=(
        "${OUTPUT_WAYBACK}/urls.txt"
        "${OUTPUT_KATANA}/urls.txt"
        "${OUTPUT_HAKRAWLER}/urls.txt"
        "${OUTPUT_HTTPX}/hosts_active.txt"
    )

    : > "${out_all}"
    local src
    for src in "${sources[@]}"; do
        if [[ -f "${src}" && -s "${src}" ]]; then
            cat "${src}" >> "${out_all}"
        fi
    done

    sort -u "${out_all}" -o "${out_all}"
    METRIC_UNIQUE_URLS="$(count_lines "${out_all}")"
    log_msg INFO "Consolidação: ${METRIC_UNIQUE_URLS} URLs únicas."
    return 0
}

# Estágio 7: Deduplicação com URO
stage_uro() {
    local in_file="${OUTPUT_CONSOLIDATED}/all_urls.txt"
    local out_file="${OUTPUT_URO}/urls_deduped.txt"

    if [[ ! -s "${in_file}" ]]; then
        log_msg WARN "Sem URLs para deduplicar."
        : > "${out_file}"
        return 0
    fi

    uro < "${in_file}" > "${out_file}" 2>> "${LOG_FILE}" || {
        log_msg ERROR "URO retornou erro — usando lista sem deduplicação."
        cp "${in_file}" "${out_file}"
        return 1
    }

    METRIC_UNIQUE_URLS="$(count_lines "${out_file}")"
    log_msg INFO "URO: ${METRIC_UNIQUE_URLS} URLs após deduplicação."
    return 0
}

# Estágio 8: Validação de URLs HTTP 200 com httpx
stage_httpx_urls() {
    local in_file="${OUTPUT_URO}/urls_deduped.txt"
    local out_json="${OUTPUT_HTTPX}/urls_200.json"
    local out_txt="${OUTPUT_HTTPX}/urls_200.txt"
    local out_params="${OUTPUT_CONSOLIDATED}/urls_parametrized.txt"

    if [[ ! -s "${in_file}" ]]; then
        log_msg WARN "Sem URLs para validar com httpx."
        : > "${out_txt}"
        : > "${out_params}"
        return 0
    fi

    run_httpx "${in_file}" "${out_json}" -mc 200 || {
        log_msg WARN "httpx (URLs 200) sem resultados."
        : > "${out_txt}"
        : > "${out_params}"
        METRIC_URLS_200=0
        return 0
    }

    parse_httpx_jsonl_urls "${out_json}" "${out_txt}"

    if [[ -s "${out_json}" ]]; then
        cp "${out_json}" "${REPORT_JSON_DIR}/httpx_urls.json"
    fi

    METRIC_URLS_200="$(count_lines "${out_txt}")"
    log_msg INFO "httpx (URLs 200): ${METRIC_URLS_200} URLs válidas."

    # Extrai URLs parametrizadas (contém ?)
    grep '?' "${out_txt}" 2>/dev/null | sort -u > "${out_params}" || : > "${out_params}"
    local param_count
    param_count="$(count_lines "${out_params}")"
    log_msg INFO "URLs parametrizadas: ${param_count}."

    return 0
}

# Estágio 9: Classificação com GF (xss, sqli, lfi, ssrf, redirect, rce)
stage_gf_patterns() {
    local in_file="${OUTPUT_CONSOLIDATED}/urls_parametrized.txt"
    local fallback="${OUTPUT_HTTPX}/urls_200.txt"
    local patterns=(xss sqli lfi ssrf redirect rce)
    local total_candidates=0

    if [[ ! -s "${in_file}" ]]; then
        log_msg WARN "Sem URLs parametrizadas — usando URLs 200 para GF."
        in_file="${fallback}"
    fi

    if [[ ! -s "${in_file}" ]]; then
        log_msg WARN "Sem URLs para GF."
        return 0
    fi

    local pattern out_file count
    for pattern in "${patterns[@]}"; do
        out_file="${OUTPUT_GF}/${pattern}.txt"
        gf "${pattern}" < "${in_file}" > "${out_file}" 2>> "${LOG_FILE}" || {
            log_msg WARN "GF pattern '${pattern}' falhou." false
            : > "${out_file}"
        }
        count="$(count_lines "${out_file}")"
        total_candidates=$((total_candidates + count))
        log_msg INFO "GF [${pattern}]: ${count} candidatos."
    done

    METRIC_VULN_CANDIDATES="${total_candidates}"
    log_msg INFO "GF total: ${METRIC_VULN_CANDIDATES} candidatos de vulnerabilidade."
    return 0
}

# Estágio 10: Varredura XSS com Dalfox (apenas candidatos GF xss)
stage_dalfox() {
    local xss_file="${OUTPUT_GF}/xss.txt"
    local out_dir="${OUTPUT_DALFOX}"
    local out_json="${OUTPUT_DALFOX}/dalfox_results.json"

    if [[ ! -s "${xss_file}" ]]; then
        log_msg WARN "Sem candidatos XSS para Dalfox."
        : > "${out_json}"
        return 0
    fi

    dalfox file "${xss_file}" \
        --silence \
        --worker "${THREADS}" \
        --delay 0 \
        --timeout "${HTTP_TIMEOUT}" \
        --format json \
        -o "${out_json}" \
        2>> "${LOG_FILE}" || {
            log_msg ERROR "Dalfox retornou erro."
            : > "${out_json}"
            return 1
        }

    # Consolida saídas JSON adicionais do Dalfox, se existirem
    find "${out_dir}" -name '*.json' -type f ! -path "${out_json}" \
        -exec cat {} + >> "${out_json}" 2>/dev/null || true

    if [[ -s "${out_json}" ]]; then
        METRIC_DALFOX_FINDINGS="$(grep -c '"type"' "${out_json}" 2>/dev/null || echo 0)"
    else
        METRIC_DALFOX_FINDINGS=0
    fi

    log_msg INFO "Dalfox: ${METRIC_DALFOX_FINDINGS} achados potenciais."
    return 0
}

# Estágio 11: Varredura com Nuclei via workflow customizado
stage_nuclei() {
    local hosts="${OUTPUT_HTTPX}/hosts_active.txt"
    local workflow="${WORKFLOW_DIR}/web-workflow.yaml"
    local out_jsonl="${OUTPUT_NUCLEI}/nuclei.jsonl"

    generate_nuclei_workflow

    if [[ ! -s "${hosts}" ]]; then
        log_msg WARN "Sem hosts ativos para Nuclei."
        : > "${out_jsonl}"
        return 0
    fi

    nuclei \
        -l "${hosts}" \
        -workflow "${workflow}" \
        -severity "${NUCLEI_SEVERITY}" \
        -silent \
        -jsonl \
        -c "${THREADS}" \
        -rl "${RATE_LIMIT}" \
        -timeout "${HTTP_TIMEOUT}" \
        -o "${out_jsonl}" \
        2>> "${LOG_FILE}" || {
            log_msg ERROR "Nuclei retornou erro."
            return 1
        }

    if [[ -f "${out_jsonl}" ]]; then
        cp "${out_jsonl}" "${REPORT_JSON_DIR}/nuclei.jsonl"
        METRIC_NUCLEI_FINDINGS="$(count_lines "${out_jsonl}")"
    else
        METRIC_NUCLEI_FINDINGS=0
    fi

    log_msg INFO "Nuclei: ${METRIC_NUCLEI_FINDINGS} achados."
    return 0
}

# =============================================================================
# RELATÓRIOS E EXPORTAÇÃO
# =============================================================================

# Gera arquivos CSV a partir dos resultados usando jq
generate_csv_reports() {
    local hosts_json="${OUTPUT_HTTPX}/hosts.json"
    local urls_json="${OUTPUT_HTTPX}/urls_200.json"
    local nuclei_jsonl="${OUTPUT_NUCLEI}/nuclei.jsonl"

    # hosts.csv (suporta JSONL do httpx)
    if [[ -f "${hosts_json}" && -s "${hosts_json}" ]]; then
        {
            echo "url,status_code,title,technologies"
            while IFS= read -r line || [[ -n "${line}" ]]; do
                [[ -z "${line}" ]] && continue
                echo "${line}" | jq -r '[.url // "", (.status_code // .status // ""), (.title // ""), ((.tech // .technologies // []) | join(";"))] | @csv' 2>/dev/null
            done < "${hosts_json}"
        } > "${REPORT_CSV_DIR}/hosts.csv" || echo "url,status_code,title,technologies" > "${REPORT_CSV_DIR}/hosts.csv"
    else
        echo "url,status_code,title,technologies" > "${REPORT_CSV_DIR}/hosts.csv"
    fi

    # urls.csv (suporta JSONL do httpx)
    if [[ -f "${urls_json}" && -s "${urls_json}" ]]; then
        {
            echo "url,status_code,content_length"
            while IFS= read -r line || [[ -n "${line}" ]]; do
                [[ -z "${line}" ]] && continue
                echo "${line}" | jq -r '[.url // "", (.status_code // .status // ""), (.content_length // .length // "")] | @csv' 2>/dev/null
            done < "${urls_json}"
        } > "${REPORT_CSV_DIR}/urls.csv" || echo "url,status_code,content_length" > "${REPORT_CSV_DIR}/urls.csv"
    else
        echo "url,status_code,content_length" > "${REPORT_CSV_DIR}/urls.csv"
    fi

    # nuclei_findings.csv
    if [[ -f "${nuclei_jsonl}" && -s "${nuclei_jsonl}" ]]; then
        {
            echo "template_id,severity,host,matched_at,description"
            while IFS= read -r line; do
                echo "${line}" | jq -r '[
                    (.template-id // .templateID // ""),
                    (.info.severity // ""),
                    (.host // ""),
                    (.matched-at // .matched // ""),
                    (.info.name // .info.description // "")
                ] | @csv' 2>/dev/null
            done < "${nuclei_jsonl}"
        } > "${REPORT_CSV_DIR}/nuclei_findings.csv"
    else
        echo "template_id,severity,host,matched_at,description" > "${REPORT_CSV_DIR}/nuclei_findings.csv"
    fi

    log_msg INFO "Relatórios CSV gerados em ${REPORT_CSV_DIR}/"
}

# Conta achados Nuclei por severidade
count_nuclei_by_severity() {
    local nuclei_file="${OUTPUT_NUCLEI}/nuclei.jsonl"
    local severity="$1"
    local count

    if [[ ! -f "${nuclei_file}" || ! -s "${nuclei_file}" ]]; then
        echo 0
        return
    fi

    count="$(jq -r --arg sev "${severity}" 'select((.info.severity // "") == $sev) | .template-id' \
        "${nuclei_file}" 2>/dev/null | wc -l | tr -d ' ')"
    echo "${count:-0}"
}

# Gera relatório final em Markdown
generate_markdown_report() {
    local summary="${REPORT_DIR}/summary.md"
    local total_duration=$(( $(date +%s) - PIPELINE_START_TIME ))
    local domains_file="${OUTPUT_CONSOLIDATED}/domains.txt"

    local nuclei_critical nuclei_high nuclei_medium nuclei_low nuclei_info
    nuclei_critical="$(count_nuclei_by_severity critical)"
    nuclei_high="$(count_nuclei_by_severity high)"
    nuclei_medium="$(count_nuclei_by_severity medium)"
    nuclei_low="$(count_nuclei_by_severity low)"
    nuclei_info="$(count_nuclei_by_severity info)"

    local gf_xss gf_sqli gf_ssrf gf_lfi gf_redirect gf_rce
    gf_xss="$(count_lines "${OUTPUT_GF}/xss.txt")"
    gf_sqli="$(count_lines "${OUTPUT_GF}/sqli.txt")"
    gf_ssrf="$(count_lines "${OUTPUT_GF}/ssrf.txt")"
    gf_lfi="$(count_lines "${OUTPUT_GF}/lfi.txt")"
    gf_redirect="$(count_lines "${OUTPUT_GF}/redirect.txt")"
    gf_rce="$(count_lines "${OUTPUT_GF}/rce.txt")"

    cat > "${summary}" <<EOF
# Relatório de Reconhecimento Web

**Data:** $(date '+%Y-%m-%d %H:%M:%S')  
**Script:** ${SCRIPT_NAME} v${SCRIPT_VERSION}  
**Tempo total:** $(format_duration "${total_duration}")

---

## Domínios Analisados

\`\`\`
$(cat "${domains_file}" 2>/dev/null || echo "N/A")
\`\`\`

## Resumo Executivo

| Métrica | Valor |
|---------|------:|
| Subdomínios encontrados | ${METRIC_SUBDOMAINS} |
| Hosts ativos | ${METRIC_ACTIVE_HOSTS} |
| URLs coletadas (únicas) | ${METRIC_UNIQUE_URLS} |
| URLs HTTP 200 | ${METRIC_URLS_200} |
| Candidatos de vulnerabilidade (GF) | ${METRIC_VULN_CANDIDATES} |
| Achados Dalfox | ${METRIC_DALFOX_FINDINGS} |
| Achados Nuclei | ${METRIC_NUCLEI_FINDINGS} |

---

## Descoberta de Subdomínios

- **Total:** ${METRIC_SUBDOMAINS}
- **Arquivo:** \`output/subfinder/subdomains.txt\`
- **JSON:** \`reports/json/subfinder.json\`

## Hosts Ativos

- **Total:** ${METRIC_ACTIVE_HOSTS}
- **Arquivo:** \`output/httpx/hosts_active.txt\`
- **JSON:** \`reports/json/httpx_hosts.json\`

## URLs Coletadas

| Fonte | Arquivo |
|-------|---------|
| Waybackurls | \`output/wayback/urls.txt\` |
| Katana | \`output/katana/urls.txt\` |
| Hakrawler | \`output/hakrawler/urls.txt\` |
| Consolidado | \`output/consolidated/all_urls.txt\` |
| Deduplicado (URO) | \`output/uro/urls_deduped.txt\` |
| HTTP 200 | \`output/httpx/urls_200.txt\` |

## Candidatos por Padrão (GF)

| Padrão | Quantidade |
|--------|----------:|
| XSS | ${gf_xss} |
| SQLi | ${gf_sqli} |
| SSRF | ${gf_ssrf} |
| LFI | ${gf_lfi} |
| Redirect | ${gf_redirect} |
| RCE | ${gf_rce} |

## Achados Dalfox

- **Total:** ${METRIC_DALFOX_FINDINGS}
- **Arquivo:** \`output/dalfox/dalfox_results.json\`

## Achados Nuclei por Severidade

| Severidade | Quantidade |
|------------|----------:|
| Critical | ${nuclei_critical} |
| High | ${nuclei_high} |
| Medium | ${nuclei_medium} |
| Low | ${nuclei_low} |
| Info | ${nuclei_info} |

- **Arquivo:** \`output/nuclei/nuclei.jsonl\`
- **CSV:** \`reports/csv/nuclei_findings.csv\`

---

## Arquivos de Exportação

| Tipo | Caminho |
|------|---------|
| JSON Subfinder | \`reports/json/subfinder.json\` |
| JSON Katana | \`reports/json/katana.jsonl\` |
| JSON httpx (hosts) | \`reports/json/httpx_hosts.json\` |
| JSON httpx (URLs) | \`reports/json/httpx_urls.json\` |
| JSON Nuclei | \`reports/json/nuclei.jsonl\` |
| CSV Hosts | \`reports/csv/hosts.csv\` |
| CSV URLs | \`reports/csv/urls.csv\` |
| CSV Nuclei | \`reports/csv/nuclei_findings.csv\` |

---

## Log de Execução

Consulte \`logs/recon.log\` para detalhes completos.

---

*Relatório gerado automaticamente por ${SCRIPT_NAME}*
EOF

    log_msg SUCCESS "Relatório Markdown: ${summary}"
}

# Estágio final: geração de todos os relatórios
stage_reports() {
    generate_csv_reports
    generate_markdown_report
    return 0
}

# Exibe métricas finais no terminal
print_final_metrics() {
    local total_duration=$(( $(date +%s) - PIPELINE_START_TIME ))
