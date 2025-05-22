#!/bin/bash

VERSION="1.1"
STRAP_URL="https://blackarch.org/strap.sh"
STRAP_SHA1="bbf0a0b838aed0ec05fff2d375dd17591cbdf8aa"

declare -r BLUE="\e[34m"
declare -r RED="\e[31m"
declare -r GREEN="\e[32m"
declare -r WHITE="\e[97m"
declare -r YELLOW="\e[33m"
declare -r NC="\e[0m"

#functions
check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root${NC}"
    exit 1
  fi
}

check_arch_based() {
  if ! command -v pacman &> /dev/null; then
    echo -e "${RED}Error: This script only works on Arch-Based systems${NC}"
    exit 1
  fi
}

print_banner() {
  clear
  cat << "EOF"
╔════════════════════════════════════╗
║         BlackArch Installer        ║
║         Version: 1.1               ║
╚════════════════════════════════════╝
EOF
  echo -e "${WHITE}by DejaVolf - Have a nice day :P 💘${NC}"
  echo -e "${WHITE}Support Arch-Based Systems${NC}"
}

install_arch_repo() {
  echo -e "${WHITE}>> Installing Arch Repository...${NC}"
  if pacman -Sy archlinux-keyring --noconfirm; then
    echo -e "${GREEN}✔ Successfullt installed Arch Keyring${NC}"
  else
    echo -e "${RED}✘ Failed to install Arch keyring${NC}"
    return 1
  fi
}

verify_checksum() {
  local file=$1
  local expected=$2
  local actual=$(sha1sum "$file" | cut -d' ' -f1)

  if [[ "$actual" != "$expected" ]]; then
    echo -e "${RED}✘ Checksum verification failed!${NC}"
    rm -rf "$file"
    return 1
  fi
  return 0
}

install_blackarch() {
  echo -e "${WHITE}>> Installing BlackArch...${NC}"

  #strap.sh
  if ! curl -L -O "$STRAP_URL"; then
    echo -e "${RED}✘ Failed to download strap.sh${NC}"
    return 1
  fi

  #verify checksum
  if ! verify_checksum "strap.sh" "$STRAP_SHA1"; then
    return 1
  fi

  chmod +x strap.sh
  if ./strap.sh; then
    echo -e "${GREEN}✔ BlackArch repository installed Successfully${NC}"
    pacman -Syu --noconfirm

    rm -f strap.sh

    echo -e "${YELLOW}>> Installation Tips:${NC}"
    echo -e "1. Install specific tools: ${WHITE} sudo pacman -S blackarch-<category>${NC}"
    echo -e "2. List categories: ${WHITE}sudo pacman -Sg | grep blackarch${NC}"
    echo -e "3. Search tools: ${WHITE}sudo pacman -Ss blackarch${NC}"
  else
    echo -e "${RED}✘ Failed to install BlackArch${NC}"
    rm -f strap.sh
    return 1
  fi
}

show_changelog() {
  cat << EOF
${WHITE}>> Changelog:${NC}
[v1.1] - 2025-05-22
- Added error handling and verification
- Improved UI and user feedback
- Added system compatibiity check
- Added installation tips

[v1.0]
- Initial Release
- Added FZF UI

[v0.3]
- Fixed BlackArch Repo installation bugs

[v0.2]
- Added support for complete BlackArch tools installation

[v0.1build23]
- Added categories, Bug fixes, Added Backdoor
EOF
}

show_about() {
  cat << EOF
${WHITE}>> About BlackArch Linux${NC}

BlackArch is a complete Linux distribution for security researchers and penetration testers.
It's built on top of Arch Linux and includes over 2800 tools for pentesting and security research.

${YELLOW}Key Features:${NC}
• Regular updates and tool additions
• Lightweight and customizable
• Compatible with existing Arch installations
• Extensive tool categories

${WHITE}Official Resources:${NC}
• Website: https://blackarch.org
• Wiki: https://wiki.blackarch.org
• Tools: https://blackarch.org/tools.html
EOF
}

#main menu :P
main_menu() {
  local options=(
    "Install Arch Repo"
    "Install BlackArch Tools"
    "View Changelog"
    "About BlackArch"
    "Exit"
  )

  while true; do
    echo -e "${BLUE}Select an option:${NC}"
    local choice=$(printf "%s\n" "${options[@]}" | fzf --height=10 --reverse --border --prompt="BlackArch Installer > " --color=border:blue)
    
    case "$choice" in
      "Install Arch Repo")
        check_root
        install_arch_repo
        read -p "Press Enter to continue..."
        print_banner
        ;;

      "Install BlackArch Tools")
        check_root
        install_blackarch
        read -p "Press Enter to continue..."
        print_banner
        ;;

      "View Changelog")
        show_changelog
        read -p "Press Enter to continue..."
        print_banner
        ;;

      "About BlackArch")
        show_about
        read -p "Press Enter to continue..."
        print_banner
        ;;

      "Exit")
        echo -e "${GREEN}Thanks for using BlackArch Installer! Bye~ 👋${NC}"
        exit 0
        ;;

      *)
        echo -e "${RED}Invalid option. Please try again.${NC}"
        sleep 1
        print_banner
        ;;
    esac
  done
}

check_arch_based
print_banner
main_menu
