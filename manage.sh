#!/usr/bin/env bash
###############################################################################
#  hs-manager.sh – Headscale/Tailscale helper (macOS & Linux)                 #
#  2025-07-13                                                                 #
###############################################################################
set -euo pipefail

HEADSCALE_URL_DEFAULT_DOMAIN="headscale.local"   # used for auto-config
HEADSCALE_CONTAINER="headscale"                  # fixed container name
LOGFILE="$HOME/hs-manager.log"
exec > >(tee -a "$LOGFILE") 2>&1

###############################################################################
# UTILS                                                                       #
###############################################################################
cmd()  { command -v "$1" &>/dev/null; }
say()  { echo -e "🟢  $*"; }
warn() { echo -e "⚠️  $*"; }
die()  { echo -e "❌  $*"; exit 1; }
ask()  { read -rp "$1 " _ans </dev/tty; echo "$_ans"; }
pause(){ read -rp "Press Enter…" </dev/tty; }

docker_ok(){ cmd docker && docker info &>/dev/null; }

install_docker(){
  say "Installing Docker..."
  case $PKG in
    brew) 
      brew install --cask docker
      say "Docker installed. Please start Docker Desktop and run this script again."
      exit 0 ;;
    apt)
      sudo apt-get update
      sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
      sudo apt-get update
      sudo apt-get install -y docker-ce docker-ce-cli containerd.io
      sudo systemctl enable docker
      sudo systemctl start docker
      sudo usermod -aG docker "$USER"
      say "Docker installed. Please log out and back in for group changes to take effect."
      ;;
    dnf|yum)
      sudo dnf install -y dnf-plugins-core
      sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
      sudo dnf install -y docker-ce docker-ce-cli containerd.io
      sudo systemctl enable docker
      sudo systemctl start docker
      sudo usermod -aG docker "$USER"
      say "Docker installed. Please log out and back in for group changes to take effect."
      ;;
    pacman)
      sudo pacman -S docker
      sudo systemctl enable docker
      sudo systemctl start docker
      sudo usermod -aG docker "$USER"
      say "Docker installed. Please log out and back in for group changes to take effect."
      ;;
    apk)
      sudo apk add docker
      sudo rc-update add docker
      sudo service docker start
      sudo addgroup "$USER" docker
      say "Docker installed. Please log out and back in for group changes to take effect."
      ;;
    *) die "Unsupported package manager for Docker installation. Please install Docker manually." ;;
  esac
}

###############################################################################
# OS / PKG manager                                                            #
###############################################################################
OS=$(uname -s)
PKG=unknown
if [[ $OS == Darwin ]]; then PKG=brew
elif [[ $OS == Linux ]];  then
  for p in apt dnf yum pacman apk; do cmd $p && { PKG=$p; break; }; done
fi

###############################################################################
# DETECT SERVER (Docker container named “headscale”)                          #
###############################################################################
SERVER_MODE=none           # docker | none
detect_server(){
  if docker_ok && docker ps --format '{{.Names}}' | grep -q "^${HEADSCALE_CONTAINER}$"; then
    SERVER_MODE=docker
  else
    SERVER_MODE=none
  fi
}
detect_server
is_server(){ [[ $SERVER_MODE == docker ]]; }

###############################################################################
# FIND FREE PORT FOR HEADSCALE                                                #
###############################################################################
find_free_port(){
  local p=8585
  while true; do
    ss -lnt | awk '{print $4}' | grep -q ":$p\$" || { echo "$p"; return; }
    ((p++))
  done
}

###############################################################################
# INITIAL SERVER SETUP                                                        #
###############################################################################
setup_server(){
  if ! docker_ok; then
    if [[ $(ask "Docker not found. Install Docker now? (Y/n):") =~ ^[Nn]$ ]]; then
      die "Docker is required for server setup."
    fi
    install_docker
    if ! docker_ok; then
      die "Docker installation failed or Docker is not running."
    fi
  fi

  if docker ps -a --format '{{.Names}}' | grep -q "^${HEADSCALE_CONTAINER}$"; then
    warn "Container ${HEADSCALE_CONTAINER} already exists – skipping setup."
    return
  fi

  PORT=$(find_free_port)
  if [[ $OS == Darwin ]]; then
    HOST_IP=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | head -1 | awk '{print $2}')
  else
    HOST_IP=$(hostname -I | awk '{print $1}')
  fi
  [[ -z $HOST_IP ]] && HOST_IP="127.0.0.1"
  SERVER_URL="http://${HOST_IP}:${PORT}"

  # Create folders
  mkdir -p ~/headscale/{config,data}

  # Generate minimal config if none exists
  CFG_FILE=~/headscale/config/config.yaml
  if [[ ! -f $CFG_FILE ]]; then
cat >"$CFG_FILE" <<EOF
server_url: ${SERVER_URL}
listen_addr: 0.0.0.0:8585
metrics_listen_addr: 127.0.0.1:9595
noise:
  private_key_path: /var/lib/headscale/noise.key
prefixes:
  v6: fd7a:115c:a1e0::/48
  v4: 100.64.0.0/10
log:
  level: info
EOF
    say "Wrote default Headscale config → $CFG_FILE"
  fi

  say "Launching Headscale on port ${PORT} …"
  docker run -d --name ${HEADSCALE_CONTAINER} \
    -p ${PORT}:8585 \
    -v ~/headscale/config:/etc/headscale \
    -v ~/headscale/data:/var/lib/headscale \
    headscale/headscale:latest \
    serve

  sleep 3
  if docker ps --format '{{.Names}}' | grep -q "^${HEADSCALE_CONTAINER}$"; then
    say "Headscale server is up on ${SERVER_URL}"
    say "To add clients, create a user and pre-auth key from the Server tools menu."
    say "Then on client machines, use option 5 to connect with the pre-auth key."
  else
    die "Failed to start Headscale container. Check Docker logs."
  fi
}

###############################################################################
# headscale WRAPPER (always inside container)                                 #
###############################################################################
hs(){
  docker exec -i "$HEADSCALE_CONTAINER" headscale "$@"
}

###############################################################################
# CLIENT-SIDE INSTALL / tailscaled control                                    #
###############################################################################
mac_cleanup(){ [[ -d /Applications/Tailscale.app ]] && sudo rm -rf /Applications/Tailscale.app; }
install_brew(){ mac_cleanup; brew install --cask tailscale; }
install_apt(){ curl -fsSL https://tailscale.com/install.sh | sh; }
install_dnf(){ curl -fsSL https://tailscale.com/install.sh | sh; }
install_yum(){ install_dnf; }
install_pacman(){ warn "Use an AUR helper (yay / paru) to install tailscale-bin"; }
install_apk(){ sudo apk add --no-cache tailscale; }

install_tailscale(){
  cmd tailscale && cmd tailscaled && { say "Tailscale already installed."; return; }
  say "Installing Tailscale…"
  case $PKG in
    brew) install_brew ;; apt) install_apt ;; dnf) install_dnf ;;
    yum) install_yum  ;; pacman) install_pacman ;; apk) install_apk ;;
    *) die "Unsupported package manager." ;;
  esac
}

running(){ pgrep -x tailscaled &>/dev/null; }
startd(){ running && { say "tailscaled already running."; return; }
         sudo tailscaled >"$HOME/tailscaled.log" 2>&1 & disown
         sleep 2; running && say "tailscaled started." || die "Failed."; }
stopd(){ running && sudo pkill tailscaled && say "tailscaled stopped." || say "tailscaled not running."; }
restartd(){ stopd; startd; }

###############################################################################
# SERVER TOOLS MENU                                                           #
###############################################################################
server_menu(){
  while true; do
cat <<SERVER_MENU
----- SERVER tools -----
1) Tail logs (docker)       5) Delete node(s)
2) List users               6) Restart container  
3) Add user                 7) Show server info
4) Make pre-auth key        8) Backup configuration
B) Back
SERVER_MENU
    read -rp "Select: " S </dev/tty
    case $S in
      1) docker logs --tail 30 "$HEADSCALE_CONTAINER";;
      2) hs users list;;
      3) U=$(ask "Username:"); [[ $U ]] && hs users create "$U";;
      4)
         echo "Users:"; hs users list | awk 'NR>1{print $1" | "$3}'
         UID=$(ask "User ID:"); [[ -z $UID ]] && continue
         hs preauthkeys create --user "$UID" --reusable --ephemeral=false;;
      5)
         echo "Nodes:"; hs nodes list | awk 'NR>1{print $1" | "$2" | "$6" | "$9}'
         IDS=$(ask "ID(s) comma-sep:"); IFS=, read -ra A <<<"$IDS"
         for id in "${A[@]}"; do [[ $id =~ ^[0-9]+$ ]] && hs nodes delete --force --node "$id"; done;;
      6) docker restart "$HEADSCALE_CONTAINER";;
      7) 
         echo "Server Information:"
         echo "Container: $HEADSCALE_CONTAINER"
         PORT=$(docker port $HEADSCALE_CONTAINER 8585/tcp 2>/dev/null | cut -d: -f2)
         [[ -z $PORT ]] && PORT="Not exposed"
         echo "Port: $PORT"
         if [[ $OS == Darwin ]]; then
           HOST_IP=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | head -1 | awk '{print $2}')
         else
           HOST_IP=$(hostname -I | awk '{print $1}')
         fi
         echo "Server URL: http://$HOST_IP:$PORT"
         echo "Config: ~/headscale/config/"
         echo "Data: ~/headscale/data/"
         ;;
      8)
         BACKUP_DIR="$HOME/headscale-backup-$(date +%Y%m%d-%H%M%S)"
         mkdir -p "$BACKUP_DIR"
         cp -r ~/headscale/* "$BACKUP_DIR/" 2>/dev/null
         say "Configuration backed up to: $BACKUP_DIR"
         ;;
      B|b) break;;
    esac
    pause
  done
}

###############################################################################
# WIPE STATE / UNINSTALL                                                      #
###############################################################################
wipe_state(){ sudo rm -rf /var/lib/tailscale && say "Local state wiped."; }

###############################################################################
# ─── FIRST-RUN: ask if this is the server ─────────────────────────────────── #
###############################################################################
if ! is_server; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "No Headscale server detected on this machine."
  echo "═══════════════════════════════════════════════════════════════"
  
  while true; do
    echo "What would you like to do?"
    echo "1) Set up this machine as a Headscale SERVER"
    echo "2) Set up this machine as a Tailscale CLIENT"
    echo "3) Continue to main menu"
    read -rp "Choice (1/2/3): " SETUP_CHOICE </dev/tty
    
    case $SETUP_CHOICE in
      1)
        setup_server
        detect_server
        break
        ;;
      2)
        install_tailscale
        say "Tailscale client installed. Use the main menu to connect to your Headscale server."
        break
        ;;
      3)
        break
        ;;
      *)
        warn "Invalid choice. Please select 1, 2, or 3."
        ;;
    esac
  done
fi

###############################################################################
# MAIN MENU                                                                   #
###############################################################################
while true; do
  clear
  echo "═════════ Headscale/Tailscale Manager – log→$LOGFILE ═════════"
  echo "Role: $(is_server && echo SERVER || echo CLIENT)   OS: $OS ($PKG)"
  [[ $SERVER_MODE == docker ]] && echo "Docker container: $HEADSCALE_CONTAINER"
  echo "══════════════════════════════════════════════════════════════"
cat <<MAIN
1) Install / Upgrade Tailscale      7) Status
2) Start tailscaled                 8) Ping node  
3) Stop tailscaled                  9) Wipe local state
4) Restart tailscaled               A) Advanced options
5) Connect to Headscale server      S) Server tools
6) Logout                           0) Quit
MAIN
  read -rp "Choice: " CH </dev/tty
  case $CH in
    1) install_tailscale; pause;;
    2) startd; pause;;
    3) stopd; pause;;
    4) restartd; pause;;
    5)
       install_tailscale; startd
       if is_server; then
         PORT=$(docker port $HEADSCALE_CONTAINER 8585/tcp 2>/dev/null | cut -d: -f2)
         [[ -z $PORT ]] && PORT=8585
         HEADSCALE_URL="http://$(hostname -I | awk '{print $1}'):$PORT"
       else
         HEADSCALE_URL=$(ask "Headscale server URL (e.g., http://192.168.1.100:8585):")
       fi
       KEY=$(ask "Pre-auth key:")
       sudo tailscale up --login-server "$HEADSCALE_URL" --authkey "$KEY" && say "Connected to Headscale!"
       pause;;
    6) sudo tailscale logout && say "Logged out."; pause;;
    7) is_server && hs nodes list || tailscale status; pause;;
    8) tailscale ping "$(ask "Node IP/name:")"; pause;;
    9) wipe_state; pause;;
    A|a)
       echo "Advanced Options:"
       echo "1) View logs    2) Check connectivity    3) Export config"
       read -rp "Choice: " ADV </dev/tty
       case $ADV in
         1) [[ -f "$HOME/tailscaled.log" ]] && tail -50 "$HOME/tailscaled.log" || echo "No log file found.";;
         2) ping -c 3 8.8.8.8 && say "Internet connectivity OK" || warn "No internet connectivity";;
         3) tailscale file get . 2>/dev/null && say "Files retrieved" || warn "No files to retrieve";;
       esac
       pause;;
    S|s) is_server && server_menu || echo "Not a server."; pause;;
    0) echo "Bye!"; exit 0;;
    *) echo "Invalid."; sleep 1;;
  esac
done
