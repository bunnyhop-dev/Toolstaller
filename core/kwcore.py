import os, sys
from time import sleep as wait
from datetime import datetime, date

today = datetime.today()
now = today.strftime("%Y %H:%M")

kw_banner = """

 __  __ __     __         ________
|  |/  |__|.--|  |.-----.|  |  |  |.---.-.----.-----.
|     <|  ||  _  ||-- __||  |  |  ||  _  |   _|  -__|
|__|\__|__||_____||_____||________||___._|__| |_____|
"""

backtomenu_banner = """

  [99] Back to KidzWare Menu
  [00] Exit the KidzWare

"""
usage = '\n[?] Use your /dev/brain lol'


def restart():
	python = sys.executable
	os.execl(python, python, * sys.argv)
	curdir = os.getcwd()

def backtomenu_option():
  print(backtomenu_banner)
  back = input("[?] KidzWare Select: ")

  if back == "99":
    restart()
  elif back == "00" or back == "0":
    sys.exit()
  else:
    print("\n[!] ERROR: Wrong Input")
    wait(2)
    restart()
################# Anti-Forensic
def afflib():
  print("\n[+] Installing Afflib\n")
  os.system('git clone https://github.com/sshock/AFFLIBv3')
  os.system('mv AFFLIBv3 ~/Documents/')
  print("\n[+] Installation Completed.")
  backtomenu_option()

def aimage():
  print("\n[!] Aimage Data Not Found.\n")
  wait(2)
  backtomenu_option()

def air():
  print("\n[+] Installing Aimage\n")
  os.system('xdg-open https://sourceforge.net/projects/air-imager/')
  print("\n[!] I don't know thy I love her.")
  backtomenu_option()

def analyzemft():
  print("\n[+] Installing Analyzemft\n")
  os.system('git clone https://github.com/dkovar/analyzeMFT')
  os.system('mv analyzeMFT ~/Documents && cd analyzeMFT && python setup.py install')
  print('\n[+] Installation Completed.')
  backtomenu_option()

def autopsy():
  print("\n[+] Installing Autopsy\n")
  os.system('git clone https://github.com/sleuthkit/autopsy')
  os.system('mv autopsy ~/Documents')
  print('\n[+] Installation Completed.')
  backtomenu_option()

def bmaptools():
  print("\n[+] Installing Bmaptools\n")
  backtomenu_option()

def bmctools():
  print()

def bulkextractor():
  print()

def canari():
  print()

def captipper():
  print()

def casefile():
  print()

def chaosmap():
  print()

def chntpw():
  print()

def chromefreak():
  print()

def dc3dd():
  print()

def dcfldd():
  print()

def ddrescue():
  print()

def dfirntfs():
  print()

def dftimewolf():
  print()

def disitool():
  print()

def dmde():
  print()

def dmgtoimg():
  print()

def dshell():
  print()

def dumpzilla():
  print()

def eindeutig():
  print()

def emldump():
  print()

def evtkit():
  print()

def exiflooter():
  print()

def extractusnjrnl():
  print()

def firefoxdecrypt():
  print()

def foremost():
  print()

def fridump():
  print()

def galleta():
  print()

def grokevt():
  print()

def guymager():
  print()

def imagemounter():
  print()

def indxtocsv():
  print()

def indxcarver():
  print()

def indxparse():
  print()

def interrogate():
  print()

def iosforensic():
  print()

def ipba2():
  print()

def iphoneanalyzer():
  print()

def lazagne():
  print()

def ldsview():
  print()

def lfle():
  print()

def libfvde():
  print()

def limeaide():
  print()

def logfileparser():
  print()

def lokiscanner():
  print()

def macrobber():
  print()

def magicrescue():
  print()

def makepdf():
  print()

def mallheur():
  print()

def maltego():
  print()

def malwaredetect():
  print()

def mboxgrep():
  print()

def mdbtools():
  print()

def memdump():
  print()

def memfetch():
  print()

def mfttocsv():
  print()

def mftcarver():
  print()

def mftcrd():
  print()

def mftreftoname():
  print()

def mimipenguin():
  print()

def mobiusft():
  print()

def mp3nema():
  print()

def mxtract():
  print()

def naft():
  print()

def networkminer():
  print()

def nfex():
  print()

def ntdsxtract():
  print()

def ntfsfileextractor():
  print()

def ntfslogtracker():
  print()

def parseevtx():
  print()

def pasco():
  print()

def pcapxray():
  print()

def pdblaster():
  print()

def pdfparser():
  print()

def pdfbookanalyzer():
  print()

def pdfid():
  print()

def pdfresurrect():
  print()

def peepdf():
  print()

def perlimageexiftool():
  print()

def pev():
  print()

def powermft():
  print()

def python2peepdf():
  print()

def rcrdcarver():
  print()

def recentfilecacheparser():
  print()

def recoverjpeg():
  print()

def recuperabit():
  print()

def regipy():
  print()

def reglookup():
  print()

def regrippy():
  print()

def rekall():
  print()

def replayproxy():
  print()

def rifiuti2():
  print()

def rkhunter():
  print()

def safecopy():
  print()

def scalpel():
  print()

def scroungentfs():
  print()

def secure2csv():
  print()

def shadowexplorer():
  print()

def skypefreak():
  print()

def sleuthkit():
  print()

def swapdigger():
  print()

def tchuntng():
  print()

def tekdefenseautomater():
  print()

def testdisk():
  print()

def thumbcacheviewer():
  print()

def trid():
  print()

def truehunter():
  print()

def unhide():
  print()

def usbrip():
  print()

def usnjrnl2csv():
  print()

def usnparser():
  print()

def vinetto():
  print()

def vipermonkey():
  print()

def volafox():
  print()

def volatilityextra():
  print()

def volatility3():
  print()

def windowsprefetchparser():
  print()

def wmiforensics():
  print()

def xplico():
  print()

def zipdump():
  print()
############################## END Anti-Forensic

##### Automation

def apt2():
  print()

def automato():
  print()

def autonessus():
  print()

def autonse():
  print()

def autopwn():
  print()

def autorecon():
  print()

def awsbucketdump():
  print()

def bashfuscator():
  print()

def blueranger():
  print()

def bopscrk():
  print()

def brutespray():
  print()

def brutex():
  print()

def byepass():
  print()

def cewl():
  print()

def cheatsh():
  print()

def checksec():
  print()

def cisco():
  print()

def clusterd():
  print()

def codeql():
  print()

def commonspeak():
  print()

def cook():
  print()

def crunch():
  print()

def deathstar():
  print()

def dorkscout():
  print()

def dracnmap():
  print()

def dump0():
  print()

def easycreds():
  print()

def easyda():
  print()

def emp3r0r():
  print()

def empire():
  print()

def findsploit():
  print()

def fstealer():
  print()

def glue():
  print()

def googleexplorer():
  print()

def gooscan():
  print()

def hackersh():
  print()

def harpoon():
  print()

def hatecrack():
  print()

def intersect():
  print()

def invokecradlecrafter():
  print()

def invokedosfucation():
  print()

def invokeobfucation():
  print()

def koadic():
  print()

def ldapscripts():
  print()

def linikatz():
  print()

def linset():
  print()

def maskprocessor():
  print()

def masscanautomation():
  print()

def massexpconsole():
  print()

def mentalist():
  print()

def merlinserver():
  print()

def metasploitautopwn():
  print()

def mitmapold():
  print()

def morpheus():
  print()

def msfmpc():
  print()

def msfenum():
  print()

def mutator():
  print()

def nettacker():
  print()

def nfspy():
  print()

def nfsshell():
  print()

def nosqlattack():
  print()

def nullscan():
  print()

def openscap():
  print()

def panoptic():
  print()

def pastejacker():
  print()

def pasvargsv():
  print()

def penbox():
  print()

def pentmenu():
  print()

def pin():
  print()

def portia():
  print()

def pupy():
  print()

def pureblood():
  print()

def pyfuscation():
  print()

def pythonarsenic():
  print()

def recomposer():
  print()

def rhodiola():
  print()

def rsmangler():
  print()

def sakis3g():
  print()

def scapsecurityguide():
  print()

def scapworkbench():
  print()

def search1337():
  print()

def shellerator():
  print()

def shellpop():
  print()

def shellz():
  print()

def simpleducky():
  print()

def sipvicious():
  print()

def sn00p():
  print()

def sn1per():
  print()

def sploitctl():
  print()

def spookflare():
  print()

def statsprocessor():
  print()

def thefatrat():
  print()

def tiger():
  print()

def tlssled():
  print()

def torctl():
  print()

def ttpassgen():
  print()

def unixprivesccheck():
  print()

def usernameanarchy():
  print()

def valhalla():
  print()

def veil():
  print()

def vlanhopping():
  print()

def voiphopper():
  print()

def wifiautopwner():
  print()

def wikigen():
  print()

def wmd():
  print()

def wnmap():
  print()
##### End Automation

##### Auto Mobile
def canutils():
  print()

def canalyzat0r():
  print()

def cantoolz():
  print()
#####End Auto Mobile

##### Backdoor
def aesshell():
  print()

def azazel():
  print()

def backcookie():
  print()

def backdoorfactory():
  print()

def backdoorme():
  print()

def backdoorppt():
  print()

def cymothoa():
  print()

def debinject():
  print()

def donut():
  print()

def dr0p1tframework():
  print()

def dragonbackdoor():
  print()

def eggshell():
  print()

def enyelkm():
  print()

def evilpdf():
  print()

def exe2image():
  print()

def gobd():
  print()

def harness():
  print()

def hotpatch():
  print()

def icmpsh():
  print()

def jynx2():
  print()

def k55():
  print()

def kimi():
  print()

def kwetza():
  print()

def idshatner():
  print()

def linuxinject():
  print()

def meterssh():
  print()

def microsploit():
  print()

def mssys():
  print()

def nxcrypt():
  print()

def phishery():
  print()

def pwncat():
  print()

def pyrasite():
  print()

def revsh():
  print()

def rrs():
  print()

def rubilyn():
  print()

def shellinabox():
  print()

def shootback():
  print()

def silenttrinity():
  print()

def syringe():
  print()

def trixd00r():
  print()

def tsh():
  print()

def tshsctp():
  print()

def u3pwn():
  print()

def unicornpowershell():
  print()

def vlany():
  print()

def webacco():
  print()

def webspa():
  print()
##### End Backdoor

##### Binary
def amber():
  print()

def amoco():
  print()

def androguard():
  print()

def angr():
  print()

def angrmanagement():
  print()

def angrpy2():
  print()

def avet():
  print()

def barf():
  print()

def bgrep():
  print()

def binaryninja():
  print()

def bindead():
  print()

def bindiff():
  print()

def binflow():
  print()

def binwally():
  print()

def bsdiff():
  print()

def bvi():
  print()

def bytecodeviewer():
  print()

def cminer():
  print()

def cpp2il():
  print()

def detectiteasy():
  print()

def dissector():
  print()

def dutas():
  print()

def dwarf():
  print()

def dynamorio():
  print()

def ecfs():
  print()

def elfkickers():
  print()

def elfparser():
  print()

def elfutils():
  print()

def eresi():
  print()

def exescan():
  print()

def expimplookup():
  print()

def expose():
  print()

def haystack():
  print()

def herculespayload():
  print()

def hex2bin():
  print()

def imagejs():
  print()

def jpegdump():
  print()

def klee():
  print()

def leena():
  print()

def loadlibrary():
  print()

def ltrace():
  print()

def maticore():
  print()

def metame():
  print()

def objdump2shellcode():
  print()

def oledump():
  print()

def packer():
  print()

def packerid():
  print()

def patchkit():
  print()

def pixd():
  print()

def powerstager():
  print()

def procdump():
  print()

def proctal():
  print()

def pythonoletools():
  print()

def python2oletools():
  print()

def quickscope():
  print()

def rbasefind():
  print()

def redress():
  print()

def saruman():
  print()

def sgn():
  print()

def soot():
  print()

def strace():
  print()

def stringsifter():
  print()

def swftools():
  print()

def triton():
  print()

def upx():
  print()

def valgrind():
  print()

def veles():
  print()

def wcc():
  print()

def wxhexeditor():
  print()

def zelos():
  print()
##### End Binary

#### Bluetooth
def bluehydra():
  print()

def bluebugger():
  print()

def bluediving():
  print()

def bluefog():
  print()

def bluelog():
  print()

def bluepot():
  print()

def blueprint():
  print()

def bluescan():
  print()

def bluesnarfer():
  print()

def bluphish():
  print()

def braces():
  print()

def bss():
  print()

def btaudit():
  print()

def btcrack():
  print()

def btlejack():
  print()

def btproxymitm():
  print()

def btscanner():
  print()

def carwhisperer():
  print()

def ghettotooth():
  print()

def hidattack():
  print()

def obexstress():
  print()

def redfang():
  print()

def spooftooph():
  print()

def tbear():
  print()

def ubertooth():
  print()
#### End Bluetooth
##### Code Autit
def bofdetector():
  print()

def brakeman():
  print()

def cflow():
  print()

def cppcheck():
  print()

def cpptest():
  print()

def detectsecrets():
  print()

def devaudit():
  print()

def dscanner():
  print()

def flawfinder():
  print()

def githound():
  print()

def graudit():
  print()

def localphp():
  print()

def mosca():
  print()

def njsscan():
  print()

def phpstan():
  print()

def pscan():
  print()

def rats():
  print()

def semgrep():
  print()

def shellcheck():
  print()

def slither():
  print()

def snyk():
  print()

def sonarscanner():
  print()

def splint():
  print()

def spotbugs():
  print()

def stoq():
  print()

def tellmeyoursecrets():
  print()

def trufflehog():
  print()

def whispers():
  print()

def wpbullet():
  print()

def wscript():
  print()

def yasca():
  print()
##### End Code Autit
#### Crakcer
def acccheck():
  print()

def adfspray():
  print()

def aesfix():
  print()

def aeskeyfind():
  print()

def against():
  print()

def asleap():
  print()

def beleth():
  print()

def bgpmd5crack():
  print()

def biosmemimage():
  print()

def bkcrack():
  print()

def bkhive():
  print()

def blackhash():
  print()

def bobthebutcher():
  print()

def bruteforce():
  print()

def bruteforceluks():
  print()

def bruteforcesaltedopenssl():
  print()

def bruteforcewallet():
  print()

def brutessh():
  print()

def chapcrack():
  print()

def cintruder():
  print()

def ciscoauditing():
  print()

def ciscoocs():
  print()

def ciscoscanner():
  print()

def cisco5crack():
  print()

def cisco7crack():
  print()

def cmospwd():
  print()

def compp():
  print()

def crackhor():
  print()

def crackle():
  print()

def crackq():
  print()

def crackserver():
  print()

def creddump():
  print()

def crowbar():
  print()

def cryptozemu():
  print()

def cudahashcat():
  print()

def cupp():
  print()

def dbpwaudit():
  print()

def depant():
  print()

def devicepharmer():
  print()

def doozer():
  print()

def dpeparser():
  print()

def eapmd5pass():
  print()

def enabler():
  print()

def evilize():
  print()

def evilmaid():
  print()

def fscrack():
  print()

def facebrute():
  print()

def fang():
  print()

def fcrackingzip():
  print()

def ftpscanner():
  print()

def gomapenum():
  print()

def gpocrack():
  print()

def hashcat():
  print()

def hasher():
  print()

def hashtag():
  print()

def hostboxssh():
  print()

def htpwdscan():
  print()

def hydra():
  print()

def ibrute():
  print()

def icludbrutter():
  print()

def iheartxor():
  print()

def iisbruteforcer():
  print()

def ikebrack():
  print()

def ikeforce():
  print()

def inguma():
  print()

def instashell():
  print()

def impipwn():
  print()

def jbrute():
  print()

def jeangrey():
  print()

def john():
  print()

def johnny():
  print()

def jwtcracker():
  print()

def jwttool():
  print()

def jwtcat():
  print()

def keimpx():
  print()

def kerbrute():
  print()

def khc():
  print()

def ldapbrute():
  print()

def levye():
  print()

def lodowep():
  print()

def mdcrack():
  print()

def medusa():
  print()

def mfoc():
  print()

def mkbrutus():
  print()

def morxbook():
  print()

def morxbrute():
  print()

def morxbtcrack():
  print()

def morxcoinpwn():
  print()

def morxcrack():
  print()

def mybff():
  print()

def ncrack():
  print()

def o365enum():
  print()

def o365spray():
  print()

def obevilion():
  print()

def oclhashcat():
  print()

def omen():
  print()

def onesixtyone():
  print()

def ophcrack():
  print()

def outlookwebapp():
  print()

def owabf():
  print()

def pack():
  print()

def passcracking():
  print()

def passepartout():
  print()

def patator():
  print()

def pdfcrack():
  print()

def pdgmail():
  print()

def pemcrack():
  print()

def pemcracker():
  print()

def phoss():
  print()

def phpmtseed():
  print()

def phprfi():
  print()

def phrasendrescher():
  print()

def pipal():
  print()

def pipeline():
  print()

def pkcrack():
  print()

def pwcrack():
  print()

def pybozocrack():
  print()

def pyrit():
  print()

def rainbowcrack():
  print()

def rarcrack():
  print()

def rcrackimt():
  print()

def rdesktopbrute():
  print()

def rdpassspray():
  print()

def ridenum():
  print()

def rloginscanner():
  print()

def rootbrute():
  print()

def rpdscan():
  print()

def rsakeyfind():
  print()

def samdump2():
  print()

def samydeluxe():
  print()

def shreder():
  print()

def sidguesser():
  print()

def sipcrack():
  print()

def skul():
  print()

def smbbf():
  print()

def snmpbrute():
  print()

def speedpwn():
  print()

def spray365():
  print()

def spraycharles():
  print()

def sqlpat():
  print()

def sshprivkeycrack():
  print()

def sshatter():
  print()

def sshprank():
  print()

def sshscan():
  print()

def sshtrix():
  print()

def sslnuke():
  print()

def sucrack():
  print()

def talon():
  print()

def tftpbruteforce():
  print()

def thckeyfinder():
  print()

def thcpptpbruter():
  print()

def thcsmartbrute():
  print()

def timeverter():
  print()

def trevospray():
  print()

def truecrack():
  print()

def tweetshell():
  print()

def ufowardriving():
  print()

def vncbypauth():
  print()

def vncrack():
  print()

def wmat():
  print()

def wordbrutepress():
  print()

def wpbf():
  print()

def wyd():
  print()

def zulu():
  print()
#### End Cracker
#### Crypto




#### End Crypto
