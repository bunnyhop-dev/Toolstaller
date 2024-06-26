import os, sys
from time import sleep as wait
from core.kkcore import *

def repo():
  print('\n[+] Adding Arch repo to your system\n')
  os.system('curl -O https://blackarch.org/strap.sh && echo 26849980b35a42e6e192c6d9ed8c46f0d6d06047 strap.sh | sha1sum -c && chmod +x strap.sh && yes | sudo ./strap.sh && yes | sudo pacman -Syyu && rm strap.sh')
  print('\n[+] Install Completed!\n')
  wait(2)
  restart_program()

def tool():
  print('\n[+] Installation BlackArch Tool\n')
  print("Category> ALL)/1.Anti-Forensic, 2.Automation, 3.AutoMobile,\n4.Backdoor, 5.Binary, 6.Bluetooth, 7.CodeAutit, 8.Cracker,9.Crypto,\n10.Cryptography, 11.Database, 12.Debugger, 13.Decompiler,14.Defensive,\n15.Disassembler, 16.Dos, 17.Drone, 18.Explotation,19.Fingerprint,\n20.Firmware, 21.Forensic, 22.Fuzzer, 23.Hardware, 24.Honeypot, 25.IDS,\n26.Keylogger, 27.Malware, 28.Misc, 29.Mobile, 30.Networking, 31.NFC,\n32.Packer, 33.Proxy, 34.Radio, 35.Recon, 36.Reversing, 37.Scan,\n38.Scanner, 39.Sniffer, 40.Social-Engineering, 41.Spoof, 42.Stego,\n43.Tunnel, 44.Unpacker, 45.Voip, 46.Web App, 47.Windows, 48.Wireless")
  print("\n[?] What's category want you to install")
  tl = input("\n🗀  > ")

  if tl.strip() == "All" or tl.strip() == "all" or tl.strip() == "ALL": all()
  elif tl.strip() == "1": antiforensic()
  elif tl.strip() == "2": automation()
  elif tl.strip() == "3": automobile()
  elif tl.strip() == "4": backdoor()
  elif tl.strip() == "5": binary()
  elif tl.strip() == "6": bluetooth()
  elif tl.strip() == "7": codeautit()
  elif tl.strip() == "8": cracker()
  elif tl.strip() == "9": crypto()
  elif tl.strip() == "10": cryptography()
  elif tl.strip() == "11": database()
  elif tl.strip() == "12": debugger()
  elif tl.strip() == "13": decompiler()
  elif tl.strip() == "14": defensive()
  elif tl.strip() == "15": disassembler()
  elif tl.strip() == "16": dos()
  elif tl.strip() == "17": drone()
  elif tl.strip() == "18": exploit()
  elif tl.strip() == "19": fingerprint()
  elif tl.strip() == "20": firmware()
  elif tl.strip() == "21": forensic()
  elif tl.strip() == "22": fuzzer()
  elif tl.strip() == "23": hardware()
  elif tl.strip() == "24": honeypot()
  elif tl.strip() == "25": ids()
  elif tl.strip() == "26": keylogger()
  elif tl.strip() == "27": malware()
  elif tl.strip() == "28": misc()
  elif tl.strip() == "29": mobile()
  elif tl.strip() == "30": network()
  elif tl.strip() == "31": nfc()
  elif tl.strip() == "32": packer()
  elif tl.strip() == "33": proxy()
  elif tl.strip() == "34": radio()
  elif tl.strip() == "35": recon()
  elif tl.strip() == "36": reverse()
  elif tl.strip() == "37": scan()
  elif tl.strip() == "38": scanner()
  elif tl.strip() == "39": sniffer()
  elif tl.strip() == "40": social()
  elif tl.strip() == "41": spoof()
  elif tl.strip() == "42": stego()
  elif tl.strip() == "43": tunnel()
  elif tl.strip() == "44": unpacker()
  elif tl.strip() == "45": voip()
  elif tl.strip() == "46": webapp()
  elif tl.strip() == "47": windows()
  elif tl.strip() == "48": wireless()
  else:
    print("\n[!] ERROR: Wrong Input\n")
    wait(2)
    restart_program()

def change():
  print("\n[?] Version 0.1build23\nAdd Category, Add Bugs, Add Backdoor\n")
  print("[?] Version 0.2\nYou can install all Blackarch tools in one comment!\n")
  print('[?] Version 0.3\nFix bug Blackarch Repo install\n')

def about():
  print("\n[+] Abot BlackArch Linux:\nBlackArch Linux is an Arch Linux-based penetration testing distribution\nfor penetration testers and security researchers.\nThe repository contains 2852 tools. You can install tools individually or in groups.")
  print('\n[!] BlackArch website: https://blackarch.org\n')

def main():
  banner()
  print('\033[1m[+] Message from dev> Have a nice day.\033[0m')
  print('\033[1m[+] Description> Easy to Install :). Support Arch Base\033[0m')
  print('\033[1m[+] BlackArch Website: https://blackarch.org \033[0m')
  print('\033[1m[+] GitHub: https://github.com/bunnyhop-dev \033[0m')
  print('\n[1] Install BlackArch repo')
  print('[2] Install BlackArch Tool')
  print('[3] Changelog')
  print('[4] About BlackArch')
  print('[0] Exit')

  sel = input("\n🗀  > ")
  if sel.strip() == "1": repo()
  elif sel.strip() == "2": tool()
  elif sel.strip() == "3": change()
  elif sel.strip() == "4": about()
  else:
    print("\n[!] ERROR: Wrong Input\n")
    wait(2)
    restart_program()

if __name__ == "__main__":
  os.system('clear')
  main()
