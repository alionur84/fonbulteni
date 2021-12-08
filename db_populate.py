from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from app import InvestmentFund, db, app
from name_handler import names_scrapper

# name handler returns in this order data_to_db, portfolio_names, fon_names, fon_codes

# this function populates the database with investment fund names scrapped from the web

def db_data_populate():
	new_data_added = []
	data = names_scrapper()[0]

	for i in range(len(data)):
		fund = InvestmentFund(fundname=data[i][1],
			fundabbrv=data[i][2],
			portfolio=data[i][0])
		name_check_query = InvestmentFund.query.filter_by(fundabbrv=data[i][2]).first()
		if name_check_query == None:
			db.session.add(fund)
			db.session.commit()
			new_data_added.append(data[i][2])
		else:
			continue

#db_data_populate()
#print(new_data_added)


