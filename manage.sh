#!/usr/bin/env bash
###############################################################################
#  hs-manager.sh – Headscale / Tailscale helper (macOS & Linux)               #
#  2025-07-13                                                                 #
###############################################################################
set -euo pipefail

HEADSCALE_DOMAIN="api.techdana.com"                 # ← change if needed
HEADSCALE_URL="https://${HEADSCALE_DOMAIN}"
HEADSCALE_CONTAINER="headscale-headscale-1"
LOGFILE="$HOME/hs-manager.log"
exec > >(tee -a "$LOGFILE") 2>&1

# ─── helpers ────────────────────────────────────────────────────────────────
cmd(){ command -v "$1" &>/dev/null; }
say(){ echo -e "🟢  $*"; }
warn(){ echo -e "⚠️  $*"; }
die(){ echo -e "❌  $*"; exit 1; }
ask(){ read -rp "$1 " _r </dev/tty; echo "$_r"; }
pause(){ read -rp "Press Enter…" </dev/tty; }

docker_ok(){ cmd docker && docker info &>/dev/null; }
is_server(){ docker_ok && docker ps --format '{{.Names}}' | grep -q "^${HEADSCALE_CONTAINER}$"; }

# ─── env detect ─────────────────────────────────────────────────────────────
OS=$(uname -s)
PKG=unknown
if [[ $OS == Darwin ]]; then PKG=brew
elif [[ $OS == Linux ]]; then
  for p in apt dnf yum pacman apk; do cmd "$p" && PKG=$p && break; done
fi

# ─── mac cleanup (legacy) ───────────────────────────────────────────────────
mac_cleanup(){
  [[ -d /Applications/Tailscale.app ]] && sudo rm -rf /Applications/Tailscale.app
  if cmd brew && brew list --cask | grep -q tailscale; then brew uninstall --cask tailscale || true; fi
  sudo rm -f /usr/local/bin/tailscale /usr/local/bin/tailscaled
}

# ─── installers ─────────────────────────────────────────────────────────────
install_brew(){ mac_cleanup; cmd brew || die "Install Homebrew first."; brew install --cask tailscale; }

install_apt(){
  CODE=$(lsb_release -c -s 2>/dev/null || . /etc/os-release; echo ${VERSION_CODENAME:-jammy})
  [[ $CODE =~ ^(bionic|focal|jammy)$ ]] || CODE=jammy
  sudo rm -f /etc/apt/sources.list.d/tailscale*.list || true
  KEY=/usr/share/keyrings/tailscale-archive-keyring.gpg
  sudo mkdir -p "$(dirname "$KEY")"
  curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/${CODE}.gpg | sudo gpg --dearmor -o "$KEY"
  echo "deb [signed-by=$KEY] https://pkgs.tailscale.com/stable/ubuntu ${CODE} main" \
    | sudo tee /etc/apt/sources.list.d/tailscale.list >/dev/null
  sudo apt -qq update
  sudo apt -qq install -y tailscale
}

install_dnf(){
  sudo dnf -y install 'dnf-command(config-manager)'
  sudo dnf config-manager --add-repo https://pkgs.tailscale.com/stable/rhel/tailscale.repo
  sudo dnf -y install tailscale
}
install_yum(){ install_dnf; }

install_pacman(){
  warn "Arch / Manjaro detected – needs an AUR helper."
  H=$(ask "AUR helper (yay/paru) or blank to cancel:"); [[ -z $H ]] && die "Abort."
  "$H" -S --noconfirm tailscale-bin
}
install_apk(){ sudo apk add --no-cache tailscale; }

install_tailscale(){
  if cmd tailscale && cmd tailscaled; then say "Tailscale already installed."; return; fi
  say "Installing Tailscale…"
  case $PKG in
    brew)   install_brew ;;
    apt)    install_apt  ;;
    dnf)    install_dnf  ;;
    yum)    install_yum  ;;
    pacman) install_pacman ;;
    apk)    install_apk  ;;
    *)      die "Unsupported OS." ;;
  esac
  say "Install done."
}

# ─── daemon control ─────────────────────────────────────────────────────────
running(){ pgrep -x tailscaled &>/dev/null; }

startd(){
  running && { say "tailscaled already running."; return; }
  if cmd systemctl && systemctl list-unit-files | grep -q tailscaled; then
    sudo systemctl enable --now tailscaled
  else
    sudo tailscaled >"$HOME/tailscaled.log" 2>&1 & disown
  fi
  sleep 2; running && say "tailscaled started." || die "Failed to start."
}

stopd(){
  running || { say "tailscaled not running."; return; }
  cmd systemctl && systemctl is-active -q tailscaled && sudo systemctl stop tailscaled || sudo pkill tailscaled
  say "tailscaled stopped."
}

restartd(){ stopd; startd; }
status(){ cmd tailscale && tailscale status || echo "Tailscale not installed."; }

# ─── server helpers ─────────────────────────────────────────────────────────
hs(){ docker exec -i "$HEADSCALE_CONTAINER" headscale "$@"; }

delete_nodes(){
  echo "Nodes (ID | Hostname | User | Status):"
  hs nodes list | awk 'NR>1{print $1" | "$2" | "$6" | "$9}'
  SEL=$(ask "ID(s) comma-sep OR all-offline:")
  if [[ $SEL == all-offline ]]; then
    hs nodes list | awk '$9=="offline"{print $1}' | while read -r id; do hs nodes delete --force --node "$id"; done
    say "Offline nodes deleted."
  else
    IFS=, read -ra IDS <<<"$SEL"
    for id in "${IDS[@]}"; do [[ $id =~ ^[0-9]+$ ]] && hs nodes delete --force --node "$id"; done
    say "Selected node(s) deleted."
  fi
}

server_menu(){
  while true; do
cat <<'SM'
----- SERVER tools -----
1) Tail logs                 4) Pre-auth key
2) List users                5) Delete node(s)
3) Add user                  6) Restart container
B) Back
SM
    read -rp "Select: " X </dev/tty
    case $X in
      1) docker logs --tail 30 "$HEADSCALE_CONTAINER" ;;
      2) hs users list ;;
      3) U=$(ask "New username:"); [[ $U ]] && hs users create "$U" ;;
      4)
         echo "Users (ID | Username):"; hs users list | awk 'NR>1{print $1" | "$3}'
         UID=$(ask "User ID:"); [[ -z $UID ]] && continue
         [[ $(ask "Reusable? (y/N):") =~ ^[Yy] ]] && RF=--reusable || RF=
         EXP=$(ask "Expiration (e.g. 90d,0=none) [90d]:")
         [[ $EXP == 0 || -z $EXP ]] && EF= || EF="--expiration $EXP"
         hs preauthkeys create --user "$UID" $RF $EF --ephemeral=false ;;
      5) delete_nodes ;;
      6) docker restart "$HEADSCALE_CONTAINER" ;;
      B|b) break ;;
      *) echo "Invalid." ;;
    esac
    pause
  done
}

wipe_state(){
  DIR=$([[ $OS == Darwin ]] && echo "$HOME/Library/Application Support/Tailscale" || echo "/var/lib/tailscale")
  warn "This deletes local identity in $DIR"
  CONF=$(ask "Type yes to confirm:"); [[ $CONF =~ ^([Yy][Ee]?[Ss]?)$ ]] || { say "Aborted."; return; }
  sudo rm -rf "$DIR" && say "State wiped."
}

uninstall(){
  sudo tailscale down --cleanup &>/dev/null || true
  stopd
  case $PKG in
    brew)  brew uninstall --cask tailscale ;;
    apt)   sudo apt remove -y tailscale ;;
    dnf|yum) sudo "$PKG" remove -y tailscale ;;
    apk)   sudo apk del tailscale ;;
  esac
  say "Tailscale binaries removed; state kept."
}

# ─── main menu ──────────────────────────────────────────────────────────────
while true; do
  clear
  echo "══════════ Headscale/Tailscale Manager ─ log→$LOGFILE ══════════"
  echo "Role: $(is_server && echo SERVER || echo CLIENT)   OS: $OS ($PKG)"
  echo "Headscale URL: $HEADSCALE_URL"
  echo "═══════════════════════════════════════════════════════════════"
cat <<'MENU'
1) Install / Upgrade Tailscale   6) Logout
2) Start tailscaled              7) Status
3) Stop tailscaled               8) Ping node
4) Restart tailscaled            9) Uninstall (keep state)
5) Login to Headscale            W) Wipe local state (new identity)
S) Server tools (if server)      0) Quit
MENU
  read -rp "Choice: " CH </dev/tty
  case $CH in
    1) install_tailscale; pause ;;
    2) startd;            pause ;;
    3) stopd;             pause ;;
    4) restartd;          pause ;;
    5)
       install_tailscale; startd
       KEY=$(ask "Pre-auth key:"); sudo tailscale up --login-server "$HEADSCALE_URL" --authkey "$KEY"
       pause ;;
    6) sudo tailscale logout && say "Logged out."; pause ;;
    7) status; pause ;;
    8) NODE=$(ask "Node IP/name:"); tailscale ping "$NODE"; pause ;;
    9) uninstall; pause ;;
    W|w) wipe_state; pause ;;
    S|s) is_server && server_menu ;;
    0) echo "Bye!"; exit 0 ;;
    *) echo "Invalid."; sleep 1 ;;
  esac
done
