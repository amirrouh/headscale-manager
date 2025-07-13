# Headscale / Tailscale Manager (`hs-manager.sh`)

A single script that installs **Tailscale**, manages the `tailscaled` daemon,
and (if you are on the Docker server) lets you administer your **Headscale**
instance – all from an easy‐to‐use menu.

---

## Features

* **Auto-detects** your OS & package manager  
  * macOS (Homebrew)  
  * Ubuntu/Debian (apt – picks the right repo & GPG key)  
  * Fedora / RHEL / CentOS (dnf | yum)  
  * Arch / Manjaro (pacman + AUR helper)  
  * Alpine (apk)
* Starts / stops / restarts **tailscaled**  
  * Uses systemd if available, else background process
* **Server tools** (when the script runs on the Docker host)  
  * Tail Headscale logs  
  * List / add users  
  * Generate **pre-auth keys** (reusable / expiring)  
  * **Delete nodes** – choose ID(s) or *all-offline*  
  * Restart the Headscale container
* **Uninstall** removes binaries but keeps `/var/lib/tailscale`
  (avoids duplicate nodes) – use **Wipe local state** if you really
  want a fresh identity.
* Clear success / error messages and automatic *Press Enter* pauses
* Full session log in `~/hs-manager.log`

---

## Quick-start

```bash
curl -o hs-manager.sh https://raw.githubusercontent.com/yourrepo/hs-manager.sh
chmod +x hs-manager.sh
./hs-manager.sh
