from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import jsonify
from flask import url_for
from flask import flash
from flask import session as login_session
from flask import make_response
from functools import wraps
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from models import Base
from models import Category
from models import Product
from models import User
import random
import string
import httplib2
import json
import requests
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import g

app = Flask(__name__)

# Grab client secrets for Google Oauth login
CLIENT_ID = json.loads(
    open('g_client_secrets.json', 'r').read())['web']['client_id']
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


# ======= User Helpers =======

# Get logged in user and make available on flask global "g"
@app.before_request
def load_user():
    if 'user_id' in login_session:
        user_id = login_session['user_id']
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = {}

    g.user = user

# Check if user is logged in, otherwise redirect to login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            flash("You are not authorized to access this area")
            return redirect('/login')
    return decorated_function


# Create New User if user in login_session doesn't exist
def createUser(login_session):
    newUser = User(username=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Get User
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Get user_id
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# ======= Auth routes =======


@app.route('/login/')
def showLogin():
    # Create anti-forgery state token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state, CLIENT_ID=CLIENT_ID)


# Connect to Google Oauth
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    request.get_data()
    code = request.data.decode('utf-8')

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('g_client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # If user doesn't exist, then create new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ''' " style = "width: 300px;
                            height: 300px;
                            border-radius: 150px;
                            -webkit-border-radius: 150px;
                            -moz-border-radius: 150px;"> '''
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect/')
def gdisconnect():
    access_token = login_session.get('access_token')

    if access_token is None:
        print 'Access Token is None'
        response = make_response(json
                                 .dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        print response
        return redirect(url_for('showCatalog'))

    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result

    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
    	response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        print response
        flash("Successfully logged out")
        return redirect(url_for('showCatalog'))
    else:
        response = make_response(
                   json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        flash("Error logging out")
        print response
        return redirect(url_for('showCatalog'))

# Facebook Oauth

# ======= Catalog Routes =======


# Home route and view
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    categories = session.query(Category).order_by(asc(Category.name))
    products = session.query(Product).order_by(asc(Product.name))
    if 'username' in login_session:
        user_id = getUserID(login_session['email'])
        user = getUserInfo(user_id)
    else:
        user = ''

    return render_template('mitt-coats.html',
                           categories=categories,
                           products=products,
                           user=user)


# Category route and view
@app.route('/category/<string:category_name>/products/')
def showCategory(category_name):
    category = session.query(Category).filter_by(
                name=category_name).one()
    products = session.query(Product).filter_by(
                category_id=category.id).all()
    categories = session.query(Category).order_by(asc(Category.name))
    return render_template('category.html',
                           category=category,
                           categories=categories,
                           products=products)


# Category new route and view
@app.route('/category/new', methods=['GET', 'POST'])
@login_required
def newCategory():
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'],
                               user_id=request.args['user_id'])
        session.add(newCategory)
        session.commit()
        flash('"%s" New Category Added' % newCategory.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('new-category.html')


# Category edit route and view
@app.route('/category/<int:category_id>/edit/',
           methods=['GET', 'POST'])
@login_required
def editCategory(category_id):
    editedCategory = session.query(Category).filter_by(id=category_id).one()
    users = session.query(User).order_by(asc(User.username))
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
        if request.form['user_id']:
            editedCategory.user_id = request.form['user_id']
        session.add(editedCategory)
        session.commit()
        flash('"%s" Category Updated' % editedCategory.name)
        return redirect(url_for('showCatalog'))

    else:
        return render_template('edit-category.html',
                               category=editedCategory,
                               users=users)


# Category delete route and view
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_id):
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        flash('"%s" Category Deleted' % categoryToDelete.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('delete-category.html',
                               category=categoryToDelete)


# Product route and view
@app.route('/category/<string:category_name>/<string:product_name>-<int:product_id>/')
def showProduct(product_id, product_name, category_name):
    product = session.query(Product).filter_by(id=product_id).one()
    return render_template('product.html', product=product)


# Product new route and view
@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def newProduct():
    categories = session.query(Category).order_by(asc(Category.name))
    if request.method == 'POST':
        newProduct = Product(name=request.form['name'],
                             description=request.form['description'],
                             price=request.form['price'],
                             category_id=request.form['category_id'],
                             user_id=request.args['user_id'])
        session.add(newProduct)
        session.commit()
        flash('"%s", New Product Added' % newProduct.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('new-product.html', categories=categories)


# Product edit route and view
@app.route('/category/<string:category_name>/<string:product_name>/edit/',
           methods=['GET', 'POST'])
@login_required
def editProduct(product_name, category_name):
    product_id = request.args.get('product_id')
    user_id = request.args.get('user_id')
    categories = session.query(Category).order_by(asc(Category.name))
    users = session.query(User).order_by(asc(User.username)).all()
    editedProduct = session.query(Product).filter_by(id=product_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedProduct.name = request.form['name']
        if request.form['description']:
            editedProduct.description = request.form['description']
        if request.form['price']:
            editedProduct.price = request.form['price']
        if request.form['user_id']:
            editedProduct.user_id = request.form['user_id']
        if request.form['category_id']:
            editedProduct.category_id = request.form['category_id']
        session.add(editedProduct)
        session.commit()
        flash('"%s", Product Updated' % editedProduct.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('edit-product.html',
                               product=editedProduct,
                               categories=categories,
                               users=users)


# Product delete route and view
@app.route('/category/<string:category_name>/<int:product_id>/delete/',
           methods=['GET', 'POST'])
@login_required
def deleteProduct(product_id, category_name):
    productToDelete = session.query(Product).filter_by(id=product_id).one()

    if login_session['user_id'] != productToDelete.user_id:
        return '''
                <script>function myFunction()
                {alert('You are not authorized to this product.');}
                </script><body onload='myFunction()''>
               '''

    if request.method == 'POST':
        session.delete(productToDelete)
        session.commit()
        flash('"%s" Product Deleted' % productToDelete.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('delete-product.html', product=productToDelete)


# ======= JSON Endpoints =======


# JSON API Endpoint - Catalog
@app.route('/catalog/JSON/')
def catalogJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


# JSON API Endpoint - Category
@app.route('/category/<int:category_id>/JSON/')
def categoryJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    return jsonify(cateogy=category.serialize)


# JSON API Endpoint - Product
@app.route('/category/<int:category_id>/product/<int:product_id>/JSON/')
def productJSON(category_id, product_id):
    product = session.query(Product).filter_by(id=product_id).one()
    return jsonify(product=product.serialize)


# JSON API Endpoint - Products
@app.route('/products/JSON/')
def productsJSON():
    products = session.query(Product).all()
    return jsonify(products=[p.serialize for p in products])


# JSON API Endpoint - User
@app.route('/users/JSON/')
def usersJSON():
    users = session.query(User).all()
    return jsonify(products=[u.serialize for u in users])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
