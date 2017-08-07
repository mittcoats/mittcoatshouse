from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from flask import session as login_session
from flask import make_response
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from models import Base, Category, Product, User
import random
import string
import httplib2
import json
import requests
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

app = Flask(__name__)

# Grab client secrets for Google Oauth login
CLIENT_ID = json.loads(
    open('gclient_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Mitt Coats House"


# Connect to Database and create database session
engine = create_engine('sqlite:///mittcoatshouse.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# JSON API Endpoint - Catalog
@app.route('/catalog/JSON')
def catalogJSON():
    return true

# JSON API Endpoint - Category
@app.route('/category/<int:category_id>/JSON')
def categoryJSON(category_id):
    return true

# JSON API Endpoint - Item
@app.route('/category/<int:category_id>/product/<int:product_id>/JSON')
def productJSON():
    return true

# JSON API Endpoint - User

# User routes
@app.route('/login')
def showLogin():
    return true


# Facebook Oauth
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    return true

@app.route('/fbdisconnect')
def fbdisconnect():
    return true

# Google Oauth
@app.route('/gconnect', methods=['POST'])
def gconnect():
    return true

@app.route('/gdisconnect')
def gdisconnect():
    return true

# Home route and view
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    categories = session.query(Category).order_by(asc(Category.name))
    # if 'username' not in login_session:
    #     return render_template('public-mitt-coats.html'), categories=categories)
    # else
    #     return render_template('mitt-coats.html'), categories=categories)
    return render_template('mitt-coats.html', categories=categories)

# Category route and view

# Category edit route and view

# Category new rouate and view

# Product route and view

# Product new route and view

# Product edit route and view

# Product delete route and view

# Get User
def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user

# Get user_id
def getUserID(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
