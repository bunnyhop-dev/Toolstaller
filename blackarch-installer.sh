#!/bin/bash

# Color
BLUE="\e[34m"
RED="\e[31m"
WHITE="\e[97m"
NC="\e[0m"

# Banner
clear
echo -e "${RED}"
echo "╔════════════════════════════╗"
echo "║ BlackArch Installer        ║"
echo "╚════════════════════════════╝"
echo -e "${WHITE}by DejaVolf - Have a nice day :) 💘${NC}"
echo -e "${WHITE}Support Arch-based ${NC}"
echo ""

# Menu options
options=(
  "Install Arch Repo"
  "Install BlackArch Tools"
  "View Changelog"
  "About BlackArch"
  "Exit"
)

while true; do
  echo -e "${BLUE}Select an option:${NC}"
  choice=$(printf "%s\n" "${options[@]}" | fzf --height=10 --reverse --border --prompt="Kidzcript Select > ")

  case "$choice" in
    "Install Arch Repo")
      echo -e "${WHITE}>> Installing Arch Repo...${NC}"
      sudo pacman -Sy archlinux-keyring --noconfirm
      ;;
    
    "Install BlackArch Tools")
      echo -e "${WHITE}>> Installing BlackArch...${NC}"
      curl -O https://blackarch.org/strap.sh
      echo bbf0a0b838aed0ec05fff2d375dd17591cbdf8aa strap.sh | sha1sum -c
      chmod +x strap.sh
      sudo ./strap.sh
      sudo pacman -Syu --noconfirm
      sleep 3
      clear
      echo -e "${RED}>>Now you can install blackarch tools from terminal\nExample 1) sudo pacman -S blackarch-fuzzy"
      ;;
    
    "View Changelog")
      echo -e "${WHITE}>> Changelog:${NC}"
      echo -e "\n[?] Version 0.1build23"
      echo "    Add Category, Add Bugs, Add Backdoor"
      echo "[?] Version 0.2"
      echo "    You can install all Blackarch tools in one comment!"
      echo "[?] Version 0.3"
      echo "    Fix bug Blackarch Repo install"
      echo "[?] Version 1.0"
      echo "    Initial Release, Added FZF UI"
      ;;
    
    "About BlackArch")
      echo -e "${WHITE}>> BlackArch is an Arch-based distro for pentesters and hackers.${NC}"
      echo "Website: https://blackarch.org"
      ;;
    
    "Exit")
      echo -e "${WHITE}Bye bye hacker~ 👋${NC}"
      exit 0
      ;;
    
    *)
      echo -e "${RED}Invalid option. Try again.${NC}"
      ;;
  esac
done
