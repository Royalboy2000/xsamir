from colorama import Fore, Style, Back
import os
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

print(f'''
                     {yl}                 .xKo.            ,kKc
                                        'OW0;         .lXNd.
                                         :OOOc       .dOOx.
                               ..        .dl:Oc     .xk:dc        ..
                               ;l         od.:k;    ok.;k;        'l.
                               :0c.      .kd. cx.  :x' ,Ol       .xk.
                               .dK0xddddk0k'  .o:.;o:   cOOxddddkKKc
                                 .;:cccc:'.    'cld:     .,:cccc:,.
                                                ....
                                                            {red}    samir Version
                                                                {wh}          
               / /   ____ __________ __   _____  / /  /  |/  /___  ____  _____/ /____  _____ {yl}
              / /   / __ `/ ___/ __ `/ | / / _ \/ /  / /|_/ / __ \/ __ \/ ___/ __/ _ \/ ___/ {ble}
    {wh}         / /___/ /_/ / /  / /_/ /| |/ /  __/ /  / /  / / /_/ / / / (__  ) /_/  __/ /
    {ble}        /_____/\__,_/_/   \__,_/ |___/\___/_/  /_/  /_/\____/_/ /_/____/\__/\___/_/  {red}V2
                                          {wh}Welcome to the {red}hell{res}
                             {gr}300${res} {ble}Lifetime{res}, {red}High Quality Private Tool{res}   
                                          
                                          
{red}[{yl}1{red}]:{res} Mass Grabber Valid All SMTPs , Twilio, Aws Keys, Nexmo, MySql

{red}[{yl}2{red}]:{res} Mass Aws Keys Quota Checker ++ Auto Root Aws Console (Admin Dashboard (RDPs,VPS, SES ...))

{red}[{yl}3{red}]:{res} Mass SMTPs Checker                            |               {red}[{yl}8{red}]:{res} Mass Advanced Dorker
                                                                      
{red}[{yl}4{red}]:{res} Mass Sendgrid Api Checker                     |               {red}[{yl}9{red}]:{res} Mass Reverse Domains => IPs
                                                                      
{red}[{yl}5{red}]:{res} Mass Twilio Checker                           |               {red}[{yl}10{red}]:{res} Mass IPS Ranger
                                                                      
{red}[{yl}6{red}]:{res} Mass Nexmo Balance Checker                    |               {red}[{yl}11{red}]:{res} Mass Laravel, Wordpress Filter

{red}[{yl}7{red}]:{res} Zone-H Grabber                                |               {red}[{yl}12{red}]:{res} MASS BYPASS & UPLOAD SHELL (LARAVEL)
                                      
                                      
''')

choice = input(f'{gr}Give Me Your Choice{wh}/{red}Xsamir> {gr}${res} ')
if choice == '1':
   link = input(f'{gr}Give Me Your List.txt{wh}/{red}Xsamir> {gr}${res} ')
if choice == '1':
    os.system(f'python3 Scripts/1/grabber.py {link}')
elif choice == '2':
    os.system('python3 Scripts/6/aws2.py')
elif choice == '3':
    os.system('python3 Scripts/2/checker.py')
elif choice == '4':
    os.system('python3 Scripts/3/sendg.py')
elif choice == '5':
    os.system('python3 Scripts/4/api.py')
elif choice == '6':
    os.system('python3 Scripts/5/nexmo.py')
elif choice == '7':
    os.system('python2 Scripts/7/zone.py')
elif choice == '8':
    os.system('python3 Scripts/11/scanner.py')
elif choice == '9':
    website = input('PLEASE PUT WEBSITE: ')
    os.system('python3 Scripts/8/ipfromdomain.py -v'+ website)
elif choice == '10':
    os.system('perl Scripts/12/ranger.pl')
elif choice == '11':
    os.system('python3 Scripts/9/laravelcms.py')
elif choice == '12':
    shell_sites = input(f'{gr}Give Me Your List.txt{wh}/{red}Xsamir> {gr}${res} ')
    os.system('python2 Scripts/13/Shellv4.py '+ shell_sites)

if choice == '13':
    print(f'Please Contact {red}samir{res} For Updates.\n                   {ble}{res}')
