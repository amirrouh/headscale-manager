#!/usr/bin/env bash
###############################################################################
#  manage.sh – Headscale / Tailscale helper (macOS & Linux)                   #
#  2025-07-13                                                                 #
###############################################################################
set -euo pipefail

###############################################################################
# USER SETTINGS                                                               #
###############################################################################
HEADSCALE_URL="https://api.techdana.com"            # Headscale public URL

# Places to look for headscale config (in container or on host)
CFG_CANDIDATES=(
  "/etc/headscale/config.yaml"
  "/etc/headscale/config/config.yaml"
  "/etc/headscale/config"
  "/var/lib/headscale/config.yaml"
  "/root/.headscale/config.yaml"
  "/home/headscale/.headscale/config.yaml"
)

LOGFILE="$HOME/hs-manager.log"
exec > >(tee -a "$LOGFILE") 2>&1

###############################################################################
# UTILITY FUNCTIONS                                                           #
###############################################################################
cmd(){ command -v "$1" &>/dev/null; }
say(){ echo -e "🟢  $*"; }
warn(){ echo -e "⚠️  $*"; }
die(){ echo -e "❌  $*"; exit 1; }
ask(){ read -rp "$1 " _ans </dev/tty; echo "$_ans"; }
pause(){ read -rp "Press Enter…" </dev/tty; }
docker_ok(){ cmd docker && docker info &>/dev/null; }

###############################################################################
# DETECT OS / PACKAGE MANAGER                                                  #
###############################################################################
OS=$(uname -s)
PKG=unknown
if [[ $OS == Darwin ]]; then
  PKG=brew
elif [[ $OS == Linux ]]; then
  for p in apt dnf yum pacman apk; do
    cmd $p && { PKG=$p; break; }
  done
fi

###############################################################################
# DETECT HEADSCALE SERVER MODE                                                #
###############################################################################
SERVER_MODE=none     # docker | binary | none
HS_CONTAINER=""      # Docker container ID if docker mode

detect_server(){
  if docker_ok; then
    if [[ -n "${HEADSCALE_CONTAINER:-}" ]] && docker inspect "$HEADSCALE_CONTAINER" &>/dev/null; then
      HS_CONTAINER="$HEADSCALE_CONTAINER"
    else
      HS_CONTAINER=$(docker ps --format '{{.ID}} {{.Image}}' \
        | grep -i headscale | awk 'NR==1{print $1}')
    fi
    if [[ -n $HS_CONTAINER ]]; then
      SERVER_MODE=docker
      return
    fi
  fi
  cmd headscale && SERVER_MODE=binary
}
detect_server
is_server(){ [[ $SERVER_MODE != none ]]; }

###############################################################################
# FIND HEADSCALE CONFIG                                                       #
###############################################################################
_CONFIG_PATH=""

find_cfg_docker(){
  local cid=$1
  for p in "${CFG_CANDIDATES[@]}"; do
    docker exec "$cid" test -f "$p" &>/dev/null && { echo "$p"; return; }
  done
  echo ""
}

find_cfg_host(){
  for p in "${CFG_CANDIDATES[@]}"; do
    [[ -f $p ]] && { echo "$p"; return; }
  done
  echo ""
}

ensure_cfg(){
  [[ -n $_CONFIG_PATH || $_CONFIG_PATH == none ]] && return
  if [[ -n "${HEADSCALE_CONFIG:-}" ]]; then
    _CONFIG_PATH="$HEADSCALE_CONFIG"
  else
    if [[ $SERVER_MODE == docker ]]; then
      _CONFIG_PATH=$(find_cfg_docker "$HS_CONTAINER")
    else
      _CONFIG_PATH=$(find_cfg_host)
    fi
    if [[ -z $_CONFIG_PATH ]]; then
      warn "Headscale config not found."
      p=$(ask "Enter config path, or blank to skip -c:")
      _CONFIG_PATH=${p:-none}
    fi
  fi
}

###############################################################################
# headscale WRAPPER                                                           #
###############################################################################
hs(){
  ensure_cfg
  if [[ $SERVER_MODE == docker ]]; then
    if [[ $_CONFIG_PATH != none ]]; then
      docker exec -i "$HS_CONTAINER" headscale -c "$_CONFIG_PATH" "$@"
    else
      docker exec -i "$HS_CONTAINER" headscale "$@"
    fi
  elif [[ $SERVER_MODE == binary ]]; then
    if [[ $_CONFIG_PATH != none ]]; then
      headscale -c "$_CONFIG_PATH" "$@"
    else
      headscale "$@"
    fi
  else
    die "This machine is not running Headscale."
  fi
}

###############################################################################
# CLIENT-SIDE: Install / Manage tailscaled                                     #
###############################################################################
mac_cleanup(){
  [[ -d /Applications/Tailscale.app ]] && sudo rm -rf /Applications/Tailscale.app
}

install_brew(){
  mac_cleanup
  cmd brew || die "Install Homebrew first."
  brew install --cask tailscale
}

install_apt(){
  CODE=$(lsb_release -c -s 2>/dev/null || echo jammy)
  [[ $CODE =~ ^(bionic|focal|jammy)$ ]] || CODE=jammy
  sudo rm -f /etc/apt/sources.list.d/tailscale*.list || true
  KEY=/usr/share/keyrings/tailscale-archive-keyring.gpg
  sudo mkdir -p "$(dirname "$KEY")"
  curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/${CODE}.gpg | sudo gpg --dearmor -o "$KEY"
  echo "deb [signed-by=$KEY] https://pkgs.tailscale.com/stable/ubuntu ${CODE} main" \
    | sudo tee /etc/apt/sources.list.d/tailscale.list >/dev/null
  sudo apt -qq update && sudo apt -qq install -y tailscale
}

install_dnf(){
  sudo dnf install -y dnf-plugins-core
  sudo dnf config-manager --add-repo https://pkgs.tailscale.com/stable/rhel/tailscale.repo
  sudo dnf install -y tailscale
}

install_yum(){ install_dnf; }
install_pacman(){
  warn "Need an AUR helper."
  H=$(ask "AUR helper (yay/paru):")
  [[ -z $H ]] && die "Abort"
  $H -S --noconfirm tailscale-bin
}
install_apk(){ sudo apk add --no-cache tailscale; }

install_tailscale(){
  cmd tailscale && cmd tailscaled && { say "Tailscale already installed."; return; }
  say "Installing Tailscale…"
  case $PKG in
    brew)    install_brew;;
    apt)     install_apt;;
    dnf)     install_dnf;;
    yum)     install_yum;;
    pacman)  install_pacman;;
    apk)     install_apk;;
    *)       die "Unsupported package manager.";;
  esac
  say "Install complete."
}

running(){ pgrep -x tailscaled &>/dev/null; }

startd(){
  running && { say "tailscaled already running."; return; }
  if cmd systemctl && systemctl list-unit-files | grep -q tailscaled; then
    sudo systemctl enable --now tailscaled
  else
    sudo tailscaled >"$HOME/tailscaled.log" 2>&1 & disown
  fi
  sleep 2
  running && say "tailscaled started." || die "Failed to start tailscaled."
}

stopd(){
  if running; then
    cmd systemctl && systemctl stop tailscaled || sudo pkill tailscaled
    say "tailscaled stopped."
  else
    say "tailscaled not running."
  fi
}

restartd(){ stopd; startd; }

status(){
  if is_server; then
    say "Headscale nodes list:"
    hs nodes list
  else
    cmd tailscale && tailscale status || echo "Tailscale not installed."
  fi
}

###############################################################################
# SERVER-ONLY FUNCTIONS                                                       #
###############################################################################
delete_nodes(){
  echo "Nodes (ID | Host | User | Status):"
  hs nodes list | awk 'NR>1{print $1" | "$2" | "$6" | "$9}'
  SEL=$(ask "ID(s) comma-sep OR all-offline:")
  if [[ $SEL == all-offline ]]; then
    hs nodes list | awk '$9=="offline"{print $1}' | while read -r id; do
      hs nodes delete --force --node "$id"
    done
    say "Offline nodes deleted."
  else
    IFS=, read -ra IDS <<<"$SEL"
    for id in "${IDS[@]}"; do
      [[ $id =~ ^[0-9]+$ ]] && hs nodes delete --force --node "$id"
    done
    say "Selected node(s) deleted."
  fi
}

server_menu(){
  while true; do
    cat <<'SMENU'
----- SERVER tools -----
1) Tail Headscale logs      4) Make pre-auth key
2) List users               5) Delete node(s)
3) Add user                 6) Restart Headscale
7) Run custom headscale cmd B) Back
SMENU
    read -rp "Select: " S </dev/tty
    case $S in
      1)
        if [[ $SERVER_MODE == docker ]]; then
          docker logs --tail 30 "$HS_CONTAINER"
        else
          sudo journalctl -u headscale -n 30 --no-pager || echo "(no journal)"
        fi
        ;;
      2) hs users list;;
      3)
        U=$(ask "New username:")
        [[ $U ]] && hs users create "$U"
        ;;
      4)
        echo "Users (ID | Username):"
        hs users list | awk 'NR>1{print $1" | "$3}'
        UID=$(ask "User ID:")
        [[ -z $UID ]] && continue
        [[ $(ask "Reusable? (y/N):") =~ ^[Yy] ]] && R=--reusable || R=
        EXP=$(ask "Expiration (90d,0=none)[90d]:")
        [[ $EXP == 0 || -z $EXP ]] && E= || E="--expiration $EXP"
        hs preauthkeys create --user "$UID" $R $E --ephemeral=false
        ;;
      5) delete_nodes;;
      6)
        if [[ $SERVER_MODE == docker ]]; then
          docker restart "$HS_CONTAINER"
        else
          sudo systemctl restart headscale
        fi
        ;;
      7)
        ARGS=$(ask "headscale args:")
        [[ $ARGS ]] && hs $ARGS
        ;;
      B|b) break;;
      *) echo "Invalid.";;
    esac
    pause
  done
}

###############################################################################
# WIPE STATE / UNINSTALL                                                      #
###############################################################################
wipe_state(){
  DIR=$([[ $OS == Darwin ]] && echo "$HOME/Library/Application Support/Tailscale" || echo "/var/lib/tailscale")
  warn "Delete local identity at $DIR"
  [[ $(ask "Type YES to confirm:") == YES ]] && sudo rm -rf "$DIR" && say "State wiped." || say "Aborted."
}

uninstall_client(){
  sudo tailscale down --cleanup &>/dev/null || true
  stopd
  case $PKG in
    brew)   brew uninstall --cask tailscale;;
    apt)    sudo apt remove -y tailscale;;
    dnf|yum)sudo $PKG remove -y tailscale;;
    pacman) warn "Manual removal via AUR helper needed.";;
    apk)    sudo apk del tailscale;;
  esac
  say "Uninstall complete (state retained)."
}

###############################################################################
# MAIN MENU                                                                   #
###############################################################################
while true; do
  clear
  echo "═════════ Headscale/Tailscale Manager – log→$LOGFILE ═════════"
  echo "Role: $(is_server && echo SERVER || echo CLIENT)   OS: $OS ($PKG)"
  [[ $SERVER_MODE == docker ]] && echo "Docker container: $HS_CONTAINER"
  echo "Headscale URL: $HEADSCALE_URL"
  echo "══════════════════════════════════════════════════════════════"
  cat <<'MAIN'
1) Install / Upgrade Tailscale   6) Logout
2) Start tailscaled              7) Status
3) Stop tailscaled               8) Ping node
4) Restart tailscaled            9) Uninstall (keep state)
5) Login to Headscale            W) Wipe local state
S) Server tools (if server)      0) Quit
MAIN

  read -rp "Choice: " CH </dev/tty
  case $CH in
    1) install_tailscale; pause;;
    2) startd; pause;;
    3) stopd; pause;;
    4) restartd; pause;;
    5)
      install_tailscale; startd
      KEY=$(ask "Pre-auth key:")
      sudo tailscale up --login-server "$HEADSCALE_URL" --authkey "$KEY"
      pause;;
    6) sudo tailscale logout && say "Logged out."; pause;;
    7) status; pause;;
    8) tailscale ping "$(ask "Node IP/name:")"; pause;;
    9) uninstall_client; pause;;
    W|w) wipe_state; pause;;
    S|s) is_server && server_menu;;
    0) echo "Bye!"; exit 0;;
    *) echo "Invalid."; sleep 1;;
  esac
done
