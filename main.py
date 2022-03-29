# Import all the modules
import os
import subprocess
import re
import hashlib
import requests
import getpass

# all banner from banner.py
os.system("cls") # change this to clear in linux and cls in windows
print("""
		     ____ ____ ____ _________ ____ ____ ____ ____ ____ 
            ||T |||H |||E |||       |||E |||A |||G |||E |||L ||
            ||__|||__|||__|||_______|||__|||__|||__|||__|||__||
            |/__\|/__\|/__\|/_______\|/__\|/__\|/__\|/__\|/__\|
    """)

def password_Security():
	print("[+] Checking the password security and complexity")
	print("[+] Checking if the password has been breached..")
	passwd = input("Enter Your password:- ")
	print("[+] Length of the password " + str(len(passwd)))
	print("[+] The password Length. The min Length is 6 and max Length is 20 ")

	# checking the password is more or less character than 8
	if len(passwd) < 8:
		print("[+] Your password is less secure. please chose a good password more than 8 character ..")
	else:
		print("[+] Your password is Good. Checking if the password complexity..")


	# checking the complexity of the password 
	if len(passwd) < 8:
		print("[*] Checking for the complexity of the password..")
	elif re.search('[0-9]', passwd) is None:
		print("[+] Your password is not complex There is no number ! please choose a good and complex password.")
	elif re.search( '[A-Z]', passwd) is None:
		print("[+] Your password is not complex There is no upper case letter's ! please choose a good and complex password.")
	elif re.search('[a-z]', passwd) is None:
		print("[+] Your password is not complex There is lower case letter's ! please choose a good and complex password")
	else:
		print("[-] Your password is complex .")

	# checking for the password breach
def password_breached():
	print("[+] Press Enter to continue to see the password breach ")
	password = getpass.getpass("Password: - ")
	hashed_pass = hashlib.sha1(password.encode('utf-8'))
	hash_str = hashed_pass.hexdigest()
	first, last = hash_str[:5].upper(), hash_str[5:].upper()
	url = 'https://api.pwnedpasswords.com/range/{}'.format(first)
	r = requests.get(url)
	if r.status_code == 200:
		content = r.content.decode('utf-8')
		hashes_list = content.splitlines()
		_dict = {}
	for _hash in hashes_list:
		split_list = _hash.split(':', 1)
		_dict[split_list[0]] = split_list[1]
	if last in _dict:
		print('[!] Bad news.. your password has been found {} times'.format(_dict[last]))
		print("=====================================================================")
		print("=================Recommendation For The Password Security=============")
		print("[=] Try to create more complex password min 6 to 20")
		print("[!] Length using all numbers from number 0-9")
		print("[-] Use all upper case from A-Z and lower case form a-z")
		print("[*] Use all the aditional special character's")
	else:
		print('[+] Yeah! Seems like your password has never been pwned!')
		print("[-] All Good This password is complex...")
		
	


	# back to main menu
	gotomain = input("Please Press Enter or Return To go back to main ")
	main()

def main():
	os.system("cls")
	choose = input("""
			[0]. Exit
			[1]. Password Security
			[2]. System Security
			[3]. Docker Security
			[4]. Cloud Security
			[5]. Email Security

			ES0.1v>>> """)


	# all the logic and condition
	if choose == "1":
		password_Security()
		password_breached()
	else:
		exit()


main()
