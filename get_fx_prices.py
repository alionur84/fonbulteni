# gets fx prices from alpha vantage api
# or from currency exchange api 
# these are displayed on homepage of the website

import json
import requests
import os



def get_usd_price():
    key = os.environ['VANTAGE_API_KEY']

    url = "https://alpha-vantage.p.rapidapi.com/query"
    headers = {
        'x-rapidapi-host': "alpha-vantage.p.rapidapi.com",
        'x-rapidapi-key': key
        }
    querystring = {"to_currency":"TRY","function":"CURRENCY_EXCHANGE_RATE","from_currency":"USD"}


    response = requests.request("GET", url, headers=headers, params=querystring)

    json_data = json.loads(response.text)
    return json_data['Realtime Currency Exchange Rate']['5. Exchange Rate']

def get_eur_price():
    key = os.environ['VANTAGE_API_KEY']

    url = "https://alpha-vantage.p.rapidapi.com/query"
    headers = {
        'x-rapidapi-host': "alpha-vantage.p.rapidapi.com",
        'x-rapidapi-key': key
        }
    querystring = {"to_currency":"TRY","function":"CURRENCY_EXCHANGE_RATE","from_currency":"EUR"}


    response = requests.request("GET", url, headers=headers, params=querystring)

    json_data = json.loads(response.text)
    return json_data['Realtime Currency Exchange Rate']['5. Exchange Rate']

def get_gbp_price():
    key = os.environ['VANTAGE_API_KEY']

    url = "https://alpha-vantage.p.rapidapi.com/query"
    headers = {
        'x-rapidapi-host': "alpha-vantage.p.rapidapi.com",
        'x-rapidapi-key': key
        }
    querystring = {"to_currency":"TRY","function":"CURRENCY_EXCHANGE_RATE","from_currency":"GBP"}


    response = requests.request("GET", url, headers=headers, params=querystring)

    json_data = json.loads(response.text)
    return json_data['Realtime Currency Exchange Rate']['5. Exchange Rate']

def get_alternative_usd_price():
    url = "https://currency-exchange.p.rapidapi.com/exchange"

    querystring = {"from":"USD","to":"TRY","q":"1.0"}

    headers = {
        'x-rapidapi-host': "currency-exchange.p.rapidapi.com",
        'x-rapidapi-key': os.environ['CURRENCY_EXCHANGE_API_KEY']
        }

    response = requests.request("GET", url, headers=headers, params=querystring)
    return response.text

def get_alternative_eur_price():
    url = "https://currency-exchange.p.rapidapi.com/exchange"

    querystring = {"from":"EUR","to":"TRY","q":"1.0"}

    headers = {
        'x-rapidapi-host': "currency-exchange.p.rapidapi.com",
        'x-rapidapi-key': os.environ['CURRENCY_EXCHANGE_API_KEY']
        }

    response = requests.request("GET", url, headers=headers, params=querystring)
    return response.text

def get_alternative_gbp_price():
    url = "https://currency-exchange.p.rapidapi.com/exchange"

    querystring = {"from":"GBP","to":"TRY","q":"1.0"}

    headers = {
        'x-rapidapi-host': "currency-exchange.p.rapidapi.com",
        'x-rapidapi-key': os.environ['CURRENCY_EXCHANGE_API_KEY']
        }

    response = requests.request("GET", url, headers=headers, params=querystring)
    return response.text

