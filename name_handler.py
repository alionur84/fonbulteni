# scraps the fon names from takasbank.com.tr


import requests
from bs4 import BeautifulSoup
from anglifier import anglify


def names_scrapper():
	first_page_url = "https://www.takasbank.com.tr/tr/kaynaklar/tefas-yatirim-fonlari"
	other_pages_url = "https://www.takasbank.com.tr/tr/kaynaklar/tefas-yatirim-fonlari?page="

	# first page url is slightly different from the rest
	# and first page is needed to find the number of total pages
	page = requests.get(first_page_url)
	soup = BeautifulSoup(page.content, "html.parser")

	# this part finds the next page button and right before it there is the number of last page
	next_page_but = soup.find('a', class_= "next" )
	number_of_pages = int(next_page_but.find_previous('a',class_=None).text)

	# write the number of pages to navigate to a variable
	pages_to_navigate = list(range(1,number_of_pages+1))

	# create a pages list fot navigate by appending urls
	pages_list = []
	for i in pages_to_navigate:
	    pages_list.append(other_pages_url+str(i))

	# create empty lists to store data
	fon_names = []
	fon_codes = []

	# scrap all urls
	for i in pages_list:
	    page = requests.get(i)
	    soup = BeautifulSoup(page.content, "html.parser")
	    fon_name = 'text-left'
	    name = soup.findAll('td', class_=fon_name) # names are found here
	    code = soup.findAll('td', class_= None ) # codes are here

	    # add the data to lists
	    for z in name:
	        eng_name = anglify(z.text) # replace Turkish characters with English ones
	        fon_names.append(eng_name)
	    for i in code:
	        fon_codes.append(i.text)

	# create portfolio names by splitting fund names.
	# first word of the fund name is portfolio name.

	portfolio_names = []

	for name in fon_names:
		name_to_be_added = name.split(' ')
		if name_to_be_added[0] in portfolio_names:
			continue
		else:
			portfolio_names.append(name_to_be_added[0])

	# prepare data in rows to be uploaded to db
	# its length gives the total number of funds

	data_to_db = []
	for item in portfolio_names:
		for count, name in enumerate(fon_names):
			name_first = name.split(' ')
			if item == name_first[0]:
				data_to_db.append([item,name,fon_codes[count]])
			else:
				continue
	# data_to_db includes [portfolio_names, fon_names, fon_codes]
	return data_to_db, portfolio_names, fon_names, fon_codes





