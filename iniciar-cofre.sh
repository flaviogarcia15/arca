#!/usr/bin/env bash
# =============================================================================
# Arca — cofre de senhas local
# Inicia um servidor HTTP somente em 127.0.0.1 e abre o navegador.
#
# Uso:   ./iniciar-cofre.sh            (porta preferida 8080)
#        ARCA_PORT=9000 ./iniciar-cofre.sh
#        ./iniciar-cofre.sh --no-browser
# Encerrar: Ctrl+C
# =============================================================================
set -Eeuo pipefail

PREFERRED_PORT="${ARCA_PORT:-8080}"
PORT_SEARCH_LIMIT=50
HOST="127.0.0.1"
APP_MARKER='name="application-name" content="arca-cofre-local"'
OPEN_BROWSER=1

for arg in "$@"; do
  case "$arg" in
    --no-browser) OPEN_BROWSER=0 ;;
    -h|--help)
      sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "Opção desconhecida: $arg (use --help)" >&2; exit 2 ;;
  esac
done

# --- Cores (somente se o terminal suportar) -----------------------------------
if [[ -t 1 ]]; then
  C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_ERR=$'\e[31m'; C_DIM=$'\e[2m'; C_BOLD=$'\e[1m'; C_RST=$'\e[0m'
else
  C_OK=''; C_WARN=''; C_ERR=''; C_DIM=''; C_BOLD=''; C_RST=''
fi
info()  { printf '%s\n' "${C_DIM}›${C_RST} $*"; }
ok()    { printf '%s\n' "${C_OK}✓${C_RST} $*"; }
warn()  { printf '%s\n' "${C_WARN}!${C_RST} $*" >&2; }
fail()  { printf '%s\n' "${C_ERR}✗ $*${C_RST}" >&2; exit 1; }

if [[ "$(id -u)" -eq 0 ]]; then
  warn "Não é necessário (nem recomendado) executar este script como root."
fi

# --- 1. Pasta do projeto, independente do diretório atual ---------------------
SCRIPT_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
PROJECT_DIR="$(dirname -- "$SCRIPT_PATH")"

# --- 2. Python 3 ----------------------------------------------------------------
PYTHON_BIN="$(command -v python3 || true)"
[[ -n "$PYTHON_BIN" ]] || fail "Python 3 não encontrado. Instale com: sudo apt install python3"
"$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)' \
  || fail "É necessário Python 3.7 ou superior (encontrado: $("$PYTHON_BIN" --version 2>&1))."

# --- 3. Arquivos essenciais -------------------------------------------------------
for f in index.html style.css app.js; do
  [[ -f "$PROJECT_DIR/$f" ]] || fail "Arquivo essencial ausente: $PROJECT_DIR/$f"
done
grep -q "$APP_MARKER" "$PROJECT_DIR/index.html" || fail "index.html não parece ser do Arca."

[[ "$PREFERRED_PORT" =~ ^[0-9]+$ ]] && (( PREFERRED_PORT >= 1024 && PREFERRED_PORT <= 65535 )) \
  || fail "Porta inválida: $PREFERRED_PORT (use 1024–65535)."

# Arquivo de estado por projeto (permite detectar uma instância já em execução)
STATE_DIR="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}"
PROJECT_HASH="$(printf '%s' "$PROJECT_DIR" | sha256sum | cut -c1-12)"
STATE_FILE="$STATE_DIR/arca-cofre-$PROJECT_HASH-$(id -u).state"

port_is_free() {
  "$PYTHON_BIN" - "$HOST" "$1" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# SO_REUSEADDR ignora conexões em TIME_WAIT, mas no Linux NÃO permite
# compartilhar a porta com outro processo que esteja escutando nela.
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind((sys.argv[1], int(sys.argv[2])))
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
}

# Confirma que a porta serve ESTE projeto (mesmo index.html), sem tocar em processos.
port_serves_this_project() {
  "$PYTHON_BIN" - "$HOST" "$1" "$PROJECT_DIR/index.html" <<'PY'
import sys, urllib.request
host, port, index_path = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(index_path, 'rb') as fh:
        expected = fh.read()
    req = urllib.request.Request(f'http://{host}:{port}/index.html', headers={'User-Agent': 'arca-launcher'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=1.5) as resp:
        sys.exit(0 if resp.read() == expected else 1)
except Exception:
    sys.exit(1)
PY
}

open_browser() {
  local url="$1"
  (( OPEN_BROWSER )) || return 0
  if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
    info "Sem ambiente gráfico detectado; abra manualmente: $url"
    return 0
  fi
  if command -v xdg-open >/dev/null 2>&1; then
    (xdg-open "$url" >/dev/null 2>&1 &) || true
  elif command -v gio >/dev/null 2>&1; then
    (gio open "$url" >/dev/null 2>&1 &) || true
  elif command -v sensible-browser >/dev/null 2>&1; then
    (sensible-browser "$url" >/dev/null 2>&1 &) || true
  else
    info "Nenhum utilitário para abrir o navegador foi encontrado; acesse: $url"
  fi
}

# --- Instância existente --------------------------------------------------------
if [[ -f "$STATE_FILE" ]]; then
  read -r OLD_PID OLD_PORT < "$STATE_FILE" || true
  if [[ "${OLD_PID:-}" =~ ^[0-9]+$ && "${OLD_PORT:-}" =~ ^[0-9]+$ ]] \
     && kill -0 "$OLD_PID" 2>/dev/null \
     && port_serves_this_project "$OLD_PORT"; then
    URL="http://$HOST:$OLD_PORT/"
    ok "O Arca já está em execução (PID $OLD_PID)."
    printf '  Endereço: %s%s%s\n' "$C_BOLD" "$URL" "$C_RST"
    open_browser "$URL"
    info "Para encerrar, use Ctrl+C no terminal onde ele foi iniciado."
    exit 0
  fi
  rm -f -- "$STATE_FILE"
fi

# --- 4/5. Porta: 8080 ou a próxima livre ---------------------------------------
PORT=""
for (( candidate = PREFERRED_PORT; candidate < PREFERRED_PORT + PORT_SEARCH_LIMIT && candidate <= 65535; candidate++ )); do
  if port_is_free "$candidate"; then PORT="$candidate"; break; fi
  if (( candidate == PREFERRED_PORT )); then
    if port_serves_this_project "$candidate"; then
      URL="http://$HOST:$candidate/"
      ok "O Arca já está sendo servido em $URL"
      open_browser "$URL"
      exit 0
    fi
    warn "Porta $candidate ocupada por outro programa; procurando outra porta livre…"
  fi
done
[[ -n "$PORT" ]] || fail "Nenhuma porta livre entre $PREFERRED_PORT e $((PREFERRED_PORT + PORT_SEARCH_LIMIT - 1))."

# --- 6. Servidor somente em 127.0.0.1, com cabeçalhos de segurança --------------
read -r -d '' SERVER_CODE <<'PY' || true
import http.server, socketserver, sys, functools

host, port, root = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ALLOWED = {'/', '/index.html', '/style.css', '/app.js', '/README.md'}

class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map,
                      '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
                      '.html': 'text/html; charset=utf-8', '.md': 'text/markdown; charset=utf-8'}

    def _allowed(self):
        path = self.path.split('?', 1)[0].split('#', 1)[0]
        if path in ALLOWED:
            return True
        self.send_error(404, 'Not Found')
        return False

    def do_GET(self):
        if self._allowed():
            super().do_GET()

    def do_HEAD(self):
        if self._allowed():
            super().do_HEAD()

    def list_directory(self, path):
        self.send_error(404, 'Not Found')
        return None

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        self.send_header('Content-Security-Policy',
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        super().end_headers()

    def log_message(self, fmt, *args):
        pass  # sem logs de acesso no terminal

class Server(socketserver.TCPServer):
    allow_reuse_address = True  # apenas TIME_WAIT; não compartilha porta em uso no Linux

handler = functools.partial(Handler, directory=root)
try:
    httpd = Server((host, port), handler)
except OSError as exc:
    print(f'Falha ao abrir a porta {port}: {exc}', file=sys.stderr)
    sys.exit(3)
print('READY', flush=True)
try:
    httpd.serve_forever(poll_interval=0.3)
except KeyboardInterrupt:
    pass
finally:
    httpd.server_close()
PY

SERVER_PID=""
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$SERVER_PID" 2>/dev/null || break
      sleep 0.2
    done
    kill -KILL "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  # Remove o arquivo de estado apenas se ele pertencer a esta execução
  if [[ -f "$STATE_FILE" ]] && [[ "$(cut -d' ' -f1 "$STATE_FILE" 2>/dev/null)" == "$SERVER_PID" ]]; then
    rm -f -- "$STATE_FILE"
  fi
  printf '\n'
  ok "Servidor encerrado."
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_server() {
  local port="$1" ready_fifo
  ready_fifo="$(mktemp -u "${STATE_DIR}/arca-ready-XXXXXX")"
  mkfifo -m 600 "$ready_fifo"
  "$PYTHON_BIN" -u - "$HOST" "$port" "$PROJECT_DIR" <<<"$SERVER_CODE" > "$ready_fifo" &
  SERVER_PID=$!
  local line=""
  if read -r -t 5 line < "$ready_fifo" && [[ "$line" == "READY" ]]; then
    rm -f -- "$ready_fifo"
    return 0
  fi
  rm -f -- "$ready_fifo"
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
  return 1
}

# Tenta iniciar; se outra aplicação ocupar a porta no meio do caminho, tenta a próxima.
STARTED=0
for (( attempt = 0; attempt < 5; attempt++ )); do
  if start_server "$PORT"; then STARTED=1; break; fi
  warn "Não foi possível usar a porta $PORT; tentando a próxima…"
  NEXT=""
  for (( candidate = PORT + 1; candidate < PREFERRED_PORT + PORT_SEARCH_LIMIT && candidate <= 65535; candidate++ )); do
    if port_is_free "$candidate"; then NEXT="$candidate"; break; fi
  done
  [[ -n "$NEXT" ]] || break
  PORT="$NEXT"
done
(( STARTED )) || fail "Não foi possível iniciar o servidor."

printf '%s %s\n' "$SERVER_PID" "$PORT" > "$STATE_FILE"
URL="http://$HOST:$PORT/"

# --- 7/8. Endereço e navegador ----------------------------------------------------
printf '\n  %sArca — cofre de senhas local%s\n' "$C_BOLD" "$C_RST"
printf '  Endereço : %s%s%s\n' "$C_BOLD" "$URL" "$C_RST"
printf '  Porta    : %s (somente %s)\n' "$PORT" "$HOST"
printf '  Pasta    : %s\n\n' "$PROJECT_DIR"
open_browser "$URL"
info "Pressione Ctrl+C para encerrar o servidor."

# --- 9/10. Mantém em execução até Ctrl+C ------------------------------------------
wait "$SERVER_PID" || true
SERVER_EXIT_PID="$SERVER_PID"
if ! kill -0 "$SERVER_EXIT_PID" 2>/dev/null; then
  warn "O servidor foi finalizado."
fi
