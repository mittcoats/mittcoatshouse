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

# Server Debugger
@app.before_request
def log_request_info():
    # app.logger.debug('Headers: %s', request.headers)
    # app.logger.debug('Body: %s', request.get_data())
    app.logger.debug('Form: %s', request.form)

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
    products = session.query(Product).order_by(asc(Product.name))

    # if 'username' not in login_session:
    #     return render_template('public-mitt-coats.html'), categories=categories)
    # else
    #     return render_template('mitt-coats.html'), categories=categories)
    return render_template('mitt-coats.html',
                            categories=categories,
                            products=products)

# Category route and view
@app.route('/category/<string:category_name>/products')
def showCategory(category_name):
    category = session.query(Category).filter_by(
                name=category_name).one()
    products = session.query(Product).filter_by(
                category_id=category.id).all()
    return render_template('category.html',
                            category=category,
                            products=products)

# Category new route and view
@app.route('/category/new', methods=['GET', 'POST'])
def newCategory():
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'])
        session.add(newCategory)
        session.commit()
        flash('New Category - %s - Added' % newCategory.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('new-category.html')

# Category edit route and view
@app.route('/category/<int:category_id>/edit',
            methods=['GET', 'POST'])
def editCategory(category_id):
    editedCategory = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
        session.add(editedCategory)
        session.commit()
        flash('Category Updated %s' % editedCategory.name)
        return redirect(url_for('showCatalog'))

    else:
        return render_template ('edit-category.html',
                            category=editedCategory)

# Category delete route and view
@app.route('/category/<int:category_id>/delete', methods=['GET', 'POST'])
def deleteCategory(category_id):
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        flash('%s Category Delete' % categoryToDelete.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('delete-category.html', category=categoryToDelete)



# Product route and view
@app.route('/category/<string:category_name>/<string:product_name>')
def showProduct(product_name, category_name):
    product = session.query(Product).filter_by(name=product_name).one()
    return render_template('product.html', product=product)

# Product new route and view
@app.route('/product/new', methods=['GET', 'POST'])
def newProduct():
    categories = session.query(Category).order_by(asc(Category.name))
    if request.method == 'POST':
        newProduct = Product(name=request.form['name'],
                             description=request.form['description'],
                             price=request.form['price'],
                             category_id=request.form['category_id'])
        session.add(newProduct)
        session.commit()
        flash('New Product - %s - Added' % newProduct.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('new-product.html', categories=categories)

# Product edit route and view
@app.route('/category/<string:category_name>/<string:product_name>-id=<int:product_id>/edit',
            methods=['GET', 'POST'])
def editProduct(product_id, product_name, category_name):
    categories = session.query(Category).order_by(asc(Category.name))
    editedProduct = session.query(Product).filter_by(id=product_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedProduct.name = request.form['name']
        if request.form['description']:
            editedProduct.description = request.form['description']
        if request.form['price']:
            editedProduct.price = request.form['price']
        if request.form['category_id']:
            editedProduct.category_id = request.form['category_id']
        session.add(editedProduct)
        session.commit()
        flash('Product Updated %s' % editedProduct.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template ('edit-product.html',
                                product=editedProduct,
                                categories=categories)

# Product delete route and view
@app.route('/category/<string:category_name>/<int:product_id>/delete',
    methods=['GET', 'POST'])
def deleteProduct(product_id, category_name):
    productToDelete = session.query(Product).filter_by(id=product_id).one()
    if request.method == 'POST':
        session.delete(productToDelete)
        session.commit()
        flash('%s Product Delete' % productToDelete.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('delete-product.html', product=productToDelete)


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
