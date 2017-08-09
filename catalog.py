#!/usr/bin/env python2.7
import json
import os
import random
import string
import time
from functools import update_wrapper
import psycopg2
import httplib2
import requests
from flask import Flask, abort, flash, g, jsonify, make_response, \
    redirect, render_template, request, \
    session as login_session, url_for
from flask_httpauth import HTTPBasicAuth
from oauth2client.client import FlowExchangeError, flow_from_clientsecrets
from redis import Redis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from dbmodels import Base, Category, Item, Manufacturer, Shop, User

auth = HTTPBasicAuth()

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = "/var/www/flaskapps/catalog/static"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

CLIENT_ID = json.loads(
        open('/var/www/flaskapps/catalog/client_secrets.json', 'r')
        .read())['web']['client_id']
APPLICATION_NAME = "is-it-vegan"


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

engine = create_engine('postgresql://catalog:catalog@localhost/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
sess = DBSession()

redis = Redis()


class RateLimit(object):
    """Limit the rate of which users can access a page"""
    expiration_window = 10

    def __init__(self, key_prefix, limit, per, send_x_headers):
        self.reset = (int(time.time()) // per) * per + per
        self.key = key_prefix + str(self.reset)
        self.limit = limit
        self.per = per
        self.send_x_headers = send_x_headers
        p = redis.pipeline()
        p.incr(self.key)
        p.expireat(self.key, self.reset + self.expiration_window)
        self.current = min(p.execute()[0], limit)

    remaining = property(lambda x: x.limit - x.current)
    over_limit = property(lambda x: x.current >= x.limit)


def get_view_rate_limit():
    return getattr(g, '_view_rate_limit', None)


def on_over_limit(limit):
    return jsonify(
            {'data': 'You hit the rate limit', 'error': '429'}), 429


def rate_limit(limit, per=300, send_x_headers=True,
               over_limit=on_over_limit,
               scope_func=lambda: request.remote_addr,
               key_func=lambda: request.endpoint):
    def decorator(f):
        def rate_limited(*args, **kwargs):
            key = 'rate-limit/%s/%s/' % (key_func(), scope_func())
            rlimit = RateLimit(key, limit, per, send_x_headers)
            g._view_rate_limit = rlimit
            if over_limit is not None and rlimit.over_limit:
                return over_limit(rlimit)
            return f(*args, **kwargs)

        return update_wrapper(rate_limited, f)

    return decorator


@app.after_request
def inject_x_rate_headers(response):
    limit = get_view_rate_limit()
    if limit and limit.send_x_headers:
        h = response.headers
        h.add('X-RateLimit-Remaining', str(limit.remaining))
        h.add('X-RateLimit-Limit', str(limit.limit))
        h.add('X-RateLimit-Reset', str(limit.reset))
    return response

"""End of RateLimit class"""


@rate_limit(limit=30, per=30 * 1)
@app.route('/api/v1/token')
@auth.login_required
def get_auth_token():
    # To test the token function
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})

"""Login function, creates anti-forgery state token"""


@rate_limit(limit=30, per=30 * 1)
@app.route('/login')
def show_login():
    menu_categories = sess.query(Category).order_by(Category.id).all()
    menu_shops = sess.query(Shop).order_by(Shop.id).all()
    menu_manufacturers = sess.query(Manufacturer) \
        .order_by(Manufacturer.id) \
        .all()
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state,
                           menu_categories=menu_categories,
                           menu_shops=menu_shops,
                           menu_manufacturers=menu_manufacturers
                           )


"""Password verification"""


@auth.verify_password
def verify_password(username_or_token, password):
    # Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = sess.query(User).filter_by(id=user_id).one()
    else:
        user = sess.query(User).filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


"""User Helper Functions"""


def create_user(login_session):
    # Make a user with oauth provider
    new_user = User(username=login_session['username'],
                    email=login_session['email'],
                    picture=login_session['picture'])
    sess.add(new_user)
    sess.commit()
    user = sess.query(User) \
        .filter_by(email=login_session['email']) \
        .one()
    return user.id


def get_user_info(user_id):
    user = sess.query(User) \
        .filter_by(id=user_id) \
        .one()
    return user


def get_user_id(email):
    try:
        user = sess.query(User) \
            .filter_by(email=email) \
            .one()
        return user.id
    except:
        return None


"""
API/JSON routes
"""

"User API"


@rate_limit(limit=30, per=30 * 1)
@app.route('/api/v1/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')
    if username is None or password is None:
        print "missing arguments"
        abort(400)

    if sess.query(User).filter_by(username=username).first() is not None:
        print "existing user"
        user = sess.query(User).filter_by(username=username).first()
        return jsonify(
                {
                    'message': 'user already exists'
                }), 200

    user = User(username=username, email=email)
    user.hash_password(password)
    sess.add(user)
    sess.commit()
    return jsonify(
            {'username': user.username}), 201


@rate_limit(limit=30, per=30 * 1)
@app.route('/api/v1/users/<int:id>')
def get_user(id):
    user = sess.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username})

"Catalog API"


@rate_limit(limit=30, per=30 * 1)
@app.route('/api/v1/JSON')
def index_json():
    category = sess.query(Category).all()
    return jsonify(
            A_title="Listing all categories:",
            categories=[c.serialize for c in category])


@rate_limit(limit=30, per=30 * 1)
@app.route('/api/v1/category/<int:category_id>/JSON')
def category_json(category_id):
    category = sess.query(Category) \
        .filter_by(id=category_id) \
        .one()
    item = sess.query(Item) \
        .filter_by(category=category_id) \
        .all()
    return jsonify(
            A_title="Here is your requested category and it's items:",
            category=[category.serialize],
            item=[i.serialize for i in item])


@rate_limit(limit=30, per=30 * 1)
@app.route('/api/v1/category/<int:category_id>/item/<int:item_id>/JSON')
def u_item_json(category_id, item_id):
    category = sess.query(Category) \
        .filter_by(id=category_id). \
        one()
    item = sess.query(Item) \
        .filter_by(category=category_id,
                   id=item_id) \
        .one()
    return jsonify(
            A_title="Here is your requested item:",
            items=[item.serialize])


@rate_limit(limit=30, per=30 * 1)
@app.route('/api/v1/shops/JSON')
def all_shops_json():
    shops = sess.query(Shop) \
        .all()
    return jsonify(
            A_title="Listing all shops:",
            shops=[s.serialize for s in shops])


@rate_limit(limit=30, per=30 * 1)
@app.route('/api/v1/shop/<int:shop_id>/JSON')
def u_shop_json(shop_id):
    u_shop = sess.query(Shop) \
        .filter_by(id=shop_id) \
        .one()
    return jsonify(
            A_title="Here is your requested shop:",
            shop=[u_shop.serialize])


@rate_limit(limit=30, per=30 * 1)
@app.route('/api/v1/manufacturers/JSON')
def all_manufacturers_json():
    manufacturers = sess.query(Manufacturer) \
        .all()
    return jsonify(
            A_title="Listing all manufacturers:",
            manufacturers=[
                m.serialize for m in manufacturers])


@rate_limit(limit=30, per=30 * 1)
@app.route('/api/v1/manufacturer/<int:manufacturer_id>/JSON')
def u_manufacturer_json(manufacturer_id):
    manufacturer = sess.query(Manufacturer) \
        .filter_by(id=manufacturer_id) \
        .one()
    return jsonify(
            A_title="Here is your requested manufacturer:",
            manufacturer=[manufacturer.serialize])


"""
End of API routes
"""


"""
Index/category routes
"""


@rate_limit(limit=30, per=30 * 1)
@app.route('/home/')
@app.route('/index/')
@app.route('/category/')
@app.route('/')
def index():
    """Menu queries"""
    menu_categories = sess.query(Category) \
        .order_by(Category.id) \
        .all()
    menu_shops = sess.query(Shop) \
        .order_by(Shop.id) \
        .all()
    menu_manufacturers = sess.query(Manufacturer) \
        .order_by(Manufacturer.id) \
        .all()
    category = sess.query(Category) \
        .all()
    return render_template('category/category_index_public.html',
                           category=category,
                           menu_categories=menu_categories,
                           menu_shops=menu_shops,
                           menu_manufacturers=menu_manufacturers)
    pass


@rate_limit(limit=30, per=30 * 1)
@app.route('/categories/<int:category_id>/')
@app.route('/category/<int:category_id>/',
           methods=['GET'])
def category(category_id):
    # Show items based on category id
    if sess.query(Category) \
        .filter_by(id=category_id) \
            .count():

        category = sess.query(Category) \
            .filter_by(id=category_id) \
            .one()

        creator = get_user_info(category.user_id)
        items = sess.query(Item) \
            .filter_by(category=category_id) \
            .all()

        """Menu queries"""
        menu_categories = sess.query(Category) \
            .order_by(Category.id) \
            .all()
        menu_shops = sess.query(Shop) \
            .order_by(Shop.id) \
            .all()
        menu_manufacturers = sess.query(Manufacturer) \
            .order_by(Manufacturer.id) \
            .all()

        if creator.id != login_session['user_id']:
            return render_template('category/category_public.html',
                                   creator=creator,
                                   item=items,
                                   category=category,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers)
        else:
            return render_template('category/category.html',
                                   creator=creator,
                                   item=items,
                                   category=category,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers)

    else:
            return redirect(url_for('index'))
pass


@auth.login_required
@rate_limit(limit=30, per=30 * 1)
@app.route('/categories/new')
@app.route('/category/new', methods=['GET', 'POST'])
def new_category():
    if 'username' not in login_session:
        return redirect('/login')
    """Menu queries"""
    menu_categories = sess.query(Category) \
        .order_by(Category.id) \
        .all()
    menu_shops = sess.query(Shop) \
        .order_by(Shop.id) \
        .all()
    menu_manufacturers = sess.query(Manufacturer) \
        .order_by(Manufacturer.id) \
        .all()
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
        if file and allowed_file(file.filename):
            target = os.path.abspath('var/www/flaskapps/catalog/static/uploads/images/')
            # target = os.path.join(APP_ROOT, 'static/')
            print(target)
            if not os.path.isdir(target):
                os.mkdir(target)
            else:
                print("Couldn't create upload directory: {}".format(target))
            print(request.files.getlist("file"))
            for upload in request.files.getlist("file"):
                print(upload)
                print("{} is the file name".format(upload.filename))
                filename = upload.filename
                destination = "/".join([target, filename])
                print ("Accept incoming file:", filename)
                print ("Save it to:", destination)
                upload.save(destination)
                print(destination)
        added_category = Category(name=request.form['name'],
                                  description=request.form['description'],
                                  up_file=upload.filename,
                                  user_id=login_session['user_id'])
        sess.add(added_category)
        sess.commit()

        return redirect(url_for('index'))
    else:
        return render_template('category/category_new.html',
                               menu_categories=menu_categories,
                               menu_shops=menu_shops,
                               menu_manufacturers=menu_manufacturers
                               )


@auth.login_required
@rate_limit(limit=30, per=30 * 1)
@app.route('/category/<int:category_id>/edit', methods=['GET', 'POST'])
def edit_category(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    if sess.query(Category.id).filter_by(id=category_id).count():
        edited_category = sess.query(Category).filter_by(id=category_id).one()
        if edited_category.user_id != login_session['user_id']:
            return redirect(url_for('index'))
        """Menu queries"""
        menu_categories = sess.query(Category) \
            .order_by(Category.id) \
            .all()
        menu_shops = sess.query(Shop) \
            .order_by(Shop.id) \
            .all()
        menu_manufacturers = sess.query(Manufacturer) \
            .order_by(Manufacturer.id) \
            .all()

        if request.method == 'POST':
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            # if user does not select file, browser also
            # submit a empty part without filename
            if file.filename == '':
                flash('No selected file')
            if file and allowed_file(file.filename):
                target = os.path.abspath('var/www/flaskapps/catalog/static/uploads/images/')
                # target = os.path.join(APP_ROOT, 'static/')
                print(target)
                if not os.path.isdir(target):
                    os.mkdir(target)
                else:
                    print("Couldn't create upload directory: {}".format(target))
                print(request.files.getlist("file"))
                for upload in request.files.getlist("file"):
                    print(upload)
                    print("{} is the file name".format(upload.filename))
                    filename = upload.filename
                    destination = "/".join([target, filename])
                    print ("Accept incoming file:", filename)
                    print ("Save it to:", destination)
                    upload.save(destination)
                    print(destination)
                    edited_category.up_file = upload.filename
            if request.form['name']:
                edited_category.name = request.form['name']
            if request.form['description']:
                edited_category.description = request.form['description']
            # check if the post request has the file part
            sess.add(edited_category)
            sess.commit()
            return redirect(url_for('category', category_id=category_id))
        else:
            return render_template('category/category_edit.html',
                                   category_id=category_id,
                                   category=edited_category,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers
                                   )

    else:
        return redirect(url_for('index'))
    pass

@auth.login_required
@rate_limit(limit=30, per=30 * 1)
@app.route('/category/<int:category_id>/delete',
           methods=['GET', 'POST'])
def delete_category(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    category = sess.query(Category) \
        .filter_by(id=category_id) \
        .one()
    if sess.query(Category) \
            .filter_by(id=category_id) \
            .one():
        if category.user_id != login_session['user_id']:
            return redirect(url_for('index'))
        """Menu queries"""
        menu_categories = sess.query(Category) \
            .order_by(Category.id) \
            .all()
        menu_shops = sess.query(Shop) \
            .order_by(Shop.id) \
            .all()
        menu_manufacturers = sess.query(Manufacturer) \
            .order_by(Manufacturer.id) \
            .all()
        if request.method == 'POST':
            sess.delete(category)
            sess.commit()
            return redirect(url_for('index'))
        else:
            return render_template('category/deleteconfirmation_category.html',
                                   category=category,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers)
        pass
    else:
        return redirect(url_for('index'))

"""
Item routes
"""


@rate_limit(limit=30, per=30 * 1)
@app.route('/category/<int:category_id>/items/<int:item_id>',
           methods=['GET', 'POST'])
def u_items(category_id, item_id):
    if sess.query(Category.id).filter_by(id=category_id).count():
        category = sess.query(Category).filter_by(id=category_id).one()
    if sess.query(Item).filter_by(category=category_id, id=item_id).count():
        item = sess.query(Item).filter_by(
            category=category_id, id=item_id).one()
        """Menu queries"""
        menu_categories = sess.query(Category) \
            .order_by(Category.id) \
            .all()
        menu_shops = sess.query(Shop) \
            .order_by(Shop.id) \
            .all()
        menu_manufacturers = sess.query(Manufacturer) \
            .order_by(Manufacturer.id) \
            .all()
        creator = get_user_info(category.user_id)
        if 'username' not in login_session \
                or creator.id != login_session['user_id']:
            return render_template('item/item_public.html',
                                   creator=creator,
                                   item=item,
                                   category=category,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers)
        else:
            return render_template('item/item.html',
                                   item=item,
                                   category=category,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers
                                   )
    else:
            return redirect(url_for('index'))
    pass


@auth.login_required
@rate_limit(limit=30, per=30 * 1)
@app.route('/category/<int:category_id>/items/new',
           methods=['GET', 'POST'])
def new_item(category_id):
    if 'username' and 'user_id' not in login_session:
        return redirect('/login')
    if sess.query(Category) \
        .filter_by(id=category_id) \
            .count():
        category = sess.query(Category) \
            .filter_by(id=category_id) \
            .one()
        """Menu queries"""
        menu_categories = sess.query(Category) \
            .order_by(Category.id) \
            .all()
        menu_shops = sess.query(Shop) \
            .order_by(Shop.id) \
            .all()
        menu_manufacturers = sess.query(Manufacturer) \
            .order_by(Manufacturer.id) \
            .all()
        if category.user_id != login_session['user_id']:
            return ("<script>function myFunction()"
                    "{alert"
                    "('You are not authorized to add items to this category.')"
                    ";}"
                    "</script>"
                    "<body onload='myFunction()''>",
                    redirect(url_for('category',
                                     category_id=category.id,
                                     menu_categories=menu_categories,
                                     menu_shops=menu_shops,
                                     menu_manufacturers=menu_manufacturers
                                     )))
        if request.method == 'POST':
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            # if user does not select file, browser also
            # submit a empty part without filename
            if file.filename == '':
                flash('No selected file')
            if file and allowed_file(file.filename):
                target = os.path.abspath('var/www/flaskapps/catalog/static/uploads/images/')
                # target = os.path.join(APP_ROOT, 'static/')
                print(target)
                if not os.path.isdir(target):
                    os.mkdir(target)
                else:
                    print("Couldn't create upload directory: {}".format(target))
                print(request.files.getlist("file"))
                for upload in request.files.getlist("file"):
                    print(upload)
                    print("{} is the file name".format(upload.filename))
                    filename = upload.filename
                    destination = "/".join([target, filename])
                    print ("Accept incoming file:", filename)
                    print ("Save it to:", destination)
                    upload.save(destination)
                    print(destination)
            new_item = Item(name=request.form['name'],
                            description=request.form['description'],
                            category=category_id,
                            ingredients=request.form['ingredients'],
                            up_file=upload.filename,
                            m_id=request.form['manufacturer_id'],
                            s_id=request.form['shop_id'],
                            user_id=login_session['user_id'])
            sess.add(new_item)
            sess.commit()

            return redirect(url_for('u_items',
                                    category_id=category.id,
                                    item_id=new_item.id))
        else:
            return render_template('item/item_new.html',
                                   category_id=category.id,
                                   category_name=category.name,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers
                                   )
        pass
    else:
        return redirect(url_for('index'))

@auth.login_required
@rate_limit(limit=30, per=30 * 1)
@app.route('/category/<int:category_id>/items/<int:item_id>/edit',
           methods=['GET', 'POST'])
def edit_item(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    if sess.query(Category.id).filter_by(id=category_id).count():
        category = sess.query(Category).filter_by(id=category_id).one()
    else:
        return redirect(url_for('index'))
    if sess.query(Item) \
            .filter_by(id=item_id) \
            .count():
        edited_item = sess.query(Item) \
            .filter_by(id=item_id) \
            .one()
        if category.user_id != login_session['user_id']:
            return ("<script>function myFunction()"
                    "{alert"
                    "('You are not authorized to edit items in this category.')"
                    ";}</script>"
                    "<body onload='myFunction()''>",
                    redirect(url_for('index')))
        """Menu queries"""
        menu_categories = sess.query(Category) \
            .order_by(Category.id) \
            .all()
        menu_shops = sess.query(Shop) \
            .order_by(Shop.id) \
            .all()
        menu_manufacturers = sess.query(Manufacturer) \
            .order_by(Manufacturer.id) \
            .all()

        if request.method == 'POST':
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            # if user does not select file, browser also
            # submit a empty part without filename
            if file.filename == '':
                flash('No selected file')
            if file and allowed_file(file.filename):
                target = os.path.abspath('var/www/flaskapps/catalog/static/uploads/images/')
                # target = os.path.join(APP_ROOT, 'static/')
                print(target)
                if not os.path.isdir(target):
                    os.mkdir(target)
                else:
                    print("Couldn't create upload directory: {}".format(target))
                print(request.files.getlist("file"))
                for upload in request.files.getlist("file"):
                    print(upload)
                    print("{} is the file name".format(upload.filename))
                    filename = upload.filename
                    destination = "/".join([target, filename])
                    print ("Accept incoming file:", filename)
                    print ("Save it to:", destination)
                    upload.save(destination)
                    print(destination)
                    edited_item.up_file = upload.filename
            if request.form['name']:
                edited_item.name = request.form['name']
            if request.form['description']:
                edited_item.description = request.form['description']
            if request.form['ingredients']:
                edited_item.ingredients = request.form['ingredients']
            sess.add(edited_item)
            sess.commit()
            return redirect(url_for('category',
                                    category_id=category.id,
                                    item_id=edited_item.id))
        return render_template('item/item_edit.html',
                               category=category,
                               item=edited_item,
                               menu_categories=menu_categories,
                               menu_shops=menu_shops,
                               menu_manufacturers=menu_manufacturers
                               )
        pass
    else:
        return redirect(url_for('index'))

@auth.login_required
@rate_limit(limit=30, per=30 * 1)
@app.route('/category/<int:category_id>/items/<int:item_id>/delete',
           methods=['GET', 'POST'])
def delete_item(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    if sess.query(Category) \
            .filter_by(id=category_id) \
            .count():
        category = sess.query(Category) \
            .filter_by(id=category_id) \
            .one()
        item_to_delete = sess.query(Item) \
            .filter_by(id=item_id) \
            .one()
    else:
        return redirect(url_for('index'))
    if category.user_id != login_session['user_id']:
        return redirect(url_for('index'))
    if sess.query(Item) \
            .filter_by(id=item_id) \
            .count():

        """Menu queries"""
        menu_categories = sess.query(Category) \
            .order_by(Category.id) \
            .all()
        menu_shops = sess.query(Shop) \
            .order_by(Shop.id) \
            .all()
        menu_manufacturers = sess.query(Manufacturer) \
            .order_by(Manufacturer.id) \
            .all()
        if request.method == 'POST':
            sess.delete(item_to_delete)
            sess.commit()
            return redirect(url_for('index'))
        else:
            return render_template('item/deleteconfirmation_item.html',
                                   item=item_to_delete,
                                   category=category,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers)
        pass
    else:
        return redirect(url_for('index'))

"""
Shop routes
"""


@rate_limit(limit=30, per=30 * 1)
@app.route('/shops/',
           methods=['GET', 'POST'])
def all_shops():
    shops = sess.query(Shop).all()
    """Menu queries"""
    menu_categories = sess.query(Category) \
        .order_by(Category.id) \
        .all()
    menu_shops = sess.query(Shop) \
        .order_by(Shop.id) \
        .all()
    menu_manufacturers = sess.query(Manufacturer) \
        .order_by(Manufacturer.id) \
        .all()
    return render_template('shop/shop_index.html', shops=shops,
                           menu_categories=menu_categories,
                           menu_shops=menu_shops,
                           menu_manufacturers=menu_manufacturers
                           )
    pass


@rate_limit(limit=30, per=30 * 1)
@app.route('/shop/<int:shop_id>/', methods=['GET', 'POST'])
def u_shop(shop_id):
    if sess.query(Shop).filter_by(id=shop_id).count():
        shop = sess.query(Shop).filter_by(id=shop_id).one()
        """Menu queries"""
        menu_categories = sess.query(Category) \
            .order_by(Category.id) \
            .all()
        menu_shops = sess.query(Shop) \
            .order_by(Shop.id) \
            .all()
        menu_manufacturers = sess.query(Manufacturer) \
            .order_by(Manufacturer.id) \
            .all()
        creator = get_user_info(shop.user_id)
        if 'username' not in login_session \
                or creator.id != login_session['user_id']:
            return render_template('shop/shop_public.html',
                                   creator=creator,
                                   shop=shop,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers
                                   )
        else:
            return render_template('shop/shop.html',
                                   shop=shop,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers
                                   )
    else:
        return redirect(url_for('index'))
    pass


@auth.login_required
@rate_limit(limit=30, per=30 * 1)
@app.route('/shops/new')
@app.route('/shop/new',
           methods=['GET', 'POST'])
def new_shop():
    if 'username' not in login_session:
        return redirect('/login')
    """Menu queries"""
    menu_categories = sess.query(Category) \
        .order_by(Category.id) \
        .all()
    menu_shops = sess.query(Shop) \
        .order_by(Shop.id) \
        .all()
    menu_manufacturers = sess.query(Manufacturer) \
        .order_by(Manufacturer.id) \
        .all()
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
        if file and allowed_file(file.filename):
            target = os.path.abspath('var/www/flaskapps/catalog/static/uploads/images/')
            # target = os.path.join(APP_ROOT, 'static/')
            print(target)
            if not os.path.isdir(target):
                os.mkdir(target)
            else:
                print("Couldn't create upload directory: {}".format(target))
            print(request.files.getlist("file"))
            for upload in request.files.getlist("file"):
                print(upload)
                print("{} is the file name".format(upload.filename))
                filename = upload.filename
                destination = "/".join([target, filename])
                print ("Accept incoming file:", filename)
                print ("Save it to:", destination)
                upload.save(destination)
                print(destination)
        shop = Shop(name=request.form['name'],
                    description=request.form['description'],
                    up_file=upload.filename,
                    id=request.form['id'],
                    user_id=login_session['user_id'])
        sess.add(shop)
        sess.commit()

        return redirect(url_for('all_shops'))
    else:
        return render_template('shop/shop_new.html',
                               menu_categories=menu_categories,
                               menu_shops=menu_shops,
                               menu_manufacturers=menu_manufacturers
                               )


@auth.login_required
@rate_limit(limit=30, per=30 * 1)
@app.route('/shop/<int:shop_id>/edit',
           methods=['GET', 'POST'])
def edit_shop(shop_id):
    if 'username' not in login_session:
        return redirect('/login')
    if sess.query(Shop.id) \
            .filter_by(id=shop_id) \
            .count():
        edited_shop = sess.query(Shop) \
            .filter_by(id=shop_id) \
            .one()
        if edited_shop.user_id != login_session['user_id']:
            return redirect(url_for('index'))
        """Menu queries"""
        menu_categories = sess.query(Category) \
            .order_by(Category.id) \
            .all()
        menu_shops = sess.query(Shop) \
            .order_by(Shop.id) \
            .all()
        menu_manufacturers = sess.query(Manufacturer) \
            .order_by(Manufacturer.id) \
            .all()

        if request.method == 'POST':
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            # if user does not select file, browser also
            # submit a empty part without filename
            if file.filename == '':
                flash('No selected file')
            if file and allowed_file(file.filename):
                target = os.path.abspath('var/www/flaskapps/catalog/static/uploads/images/')
                # target = os.path.join(APP_ROOT, 'static/')
                print(target)
                if not os.path.isdir(target):
                    os.mkdir(target)
                else:
                    print("Couldn't create upload directory: {}".format(target))
                print(request.files.getlist("file"))
                for upload in request.files.getlist("file"):
                    print(upload)
                    print("{} is the file name".format(upload.filename))
                    filename = upload.filename
                    destination = "/".join([target, filename])
                    print ("Accept incoming file:", filename)
                    print ("Save it to:", destination)
                    upload.save(destination)
                    print(destination)
                    edited_shop.up_file = upload.filename
            if request.form['name']:
                edited_shop.name = request.form['name']
            if request.form['description']:
                edited_shop.description = request.form['description']
            sess.add(edited_shop)
            sess.commit()
            return redirect(url_for('u_shop',
                                    shop_id=edited_shop.id))
        else:
            return render_template('shop/shop_edit.html',
                                   shop=edited_shop,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers
                                   )
        pass
    else:
        return redirect(url_for('index'))

@auth.login_required
@rate_limit(limit=30, per=30 * 1)
@app.route('/shop/<int:shop_id>/delete',
           methods=['GET', 'POST'])
def delete_shop(shop_id):
    if 'username' not in login_session:
        return redirect('/login')
    if sess.query(Shop) \
        .filter_by(id=shop_id) \
            .count():
        shop = sess.query(Shop) \
            .filter_by(id=shop_id) \
            .one()
        if shop.user_id != login_session['user_id']:
            return redirect('/index')
        """Menu queries"""
        menu_categories = sess.query(Category) \
            .order_by(Category.id) \
            .all()
        menu_shops = sess.query(Shop) \
            .order_by(Shop.id) \
            .all()
        menu_manufacturers = sess.query(Manufacturer) \
            .order_by(Manufacturer.id) \
            .all()

        if request.method == 'POST':
            sess.delete(shop)
            sess.commit()
            return redirect(url_for('all_shops',
                                    menu_categories=menu_categories,
                                    menu_shops=menu_shops,
                                    menu_manufacturers=menu_manufacturers
                                    ))
        else:
            return render_template('shop/deleteconfirmation_shop.html',
                                   shop=shop,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers)
        pass
    return redirect(url_for('index'))


"""
Manufacturer routes
"""


@rate_limit(limit=30, per=30 * 1)
@app.route('/manufacturers/',
           methods=['GET', 'POST'])
def all_manufacturers():
    manufacturers = sess.query(Manufacturer) \
        .all()
    """Menu queries"""
    menu_categories = sess.query(Category) \
        .order_by(Category.id) \
        .all()
    menu_shops = sess.query(Shop) \
        .order_by(Shop.id) \
        .all()
    menu_manufacturers = sess.query(Manufacturer) \
        .order_by(Manufacturer.id) \
        .all()
    return render_template('manufacturer/manufacturer_index.html',
                           manufactureres=manufacturers,
                           menu_categories=menu_categories,
                           menu_shops=menu_shops,
                           menu_manufacturers=menu_manufacturers
                           )
    pass


@rate_limit(limit=30, per=30 * 1)
@app.route('/manufacturer/<int:manufacturer_id>/',
           methods=['GET', 'POST'])
def u_manufacturer(manufacturer_id):

    if sess.query(Manufacturer) \
        .filter_by(id=manufacturer_id) \
            .count():
        manufacturer = sess.query(Manufacturer) \
            .filter_by(id=manufacturer_id) \
            .one()
        creator = get_user_info(manufacturer.user_id)
        """"Menu queries"""
        menu_categories = sess.query(Category) \
            .order_by(Category.id) \
            .all()
        menu_shops = sess.query(Shop) \
            .order_by(Shop.id) \
            .all()
        menu_manufacturers = sess.query(Manufacturer) \
            .order_by(Manufacturer.id) \
            .all()
        if 'username' not in login_session \
                or creator.id != login_session['user_id']:
            return render_template('manufacturer/manufacturer_public.html',
                                   creator=creator,
                                   manufacturer=manufacturer,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers
                                   )
        else:
            return render_template('manufacturer/manufacturer.html',
                                   manufacturer=manufacturer,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers
                                   )
    else:
        return redirect(url_for('index'))
    pass


@auth.login_required
@rate_limit(limit=30, per=30 * 1)
@app.route('/manufacturers/new')
@app.route('/manufacturer/new',
           methods=['GET', 'POST'])
def new_manufacturer():
    if 'username' not in login_session:
        return redirect('/login')
    """Menu queries"""
    menu_categories = sess.query(Category) \
        .order_by(Category.id) \
        .all()
    menu_shops = sess.query(Shop) \
        .order_by(Shop.id) \
        .all()
    menu_manufacturers = sess.query(Manufacturer) \
        .order_by(Manufacturer.id) \
        .all()
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
        if file and allowed_file(file.filename):
            target = os.path.abspath('var/www/flaskapps/catalog/static/uploads/images/')
            # target = os.path.join(APP_ROOT, 'static/')
            print(target)
            if not os.path.isdir(target):
                os.mkdir(target)
            else:
                print("Couldn't create upload directory: {}".format(target))
            print(request.files.getlist("file"))
            for upload in request.files.getlist("file"):
                print(upload)
                print("{} is the file name".format(upload.filename))
                filename = upload.filename
                destination = "/".join([target, filename])
                print ("Accept incoming file:", filename)
                print ("Save it to:", destination)
                upload.save(destination)
                print(destination)
        new_manufacturer = Manufacturer(
                name=request.form['name'],
                description=request.form['description'],
                up_file=upload.filename,
                id=request.form['id'],
                user_id=login_session['user_id'])
        sess.add(new_manufacturer)
        sess.commit()

        return redirect(url_for('all_manufacturers'))
    else:
        return render_template('manufacturer/manufacturer_new.html',
                               menu_categories=menu_categories,
                               menu_shops=menu_shops,
                               menu_manufacturers=menu_manufacturers
                               )


@auth.login_required
@rate_limit(limit=30, per=30 * 1)
@app.route('/manufacturer/<int:manufacturer_id>/edit',
           methods=['GET', 'POST'])
def edit_manufacturer(manufacturer_id):
    if 'username' not in login_session:
        return redirect('/login')
    if sess.query(Manufacturer) \
            .filter_by(id=manufacturer_id) \
            .count():
        edited_manufacturer = sess.query(Manufacturer) \
            .filter_by(id=manufacturer_id) \
            .one()
        if edited_manufacturer.user_id != login_session['user_id']:
            return redirect('/index')
        """Menu queries"""
        menu_categories = sess.query(Category) \
            .order_by(Category.id) \
            .all()
        menu_shops = sess.query(Shop) \
            .order_by(Shop.id) \
            .all()
        menu_manufacturers = sess.query(Manufacturer) \
            .order_by(Manufacturer.id) \
            .all()

        if request.method == 'POST':
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            # if user does not select file, browser also
            # submit a empty part without filename
            if file.filename == '':
                flash('No selected file')
            if file and allowed_file(file.filename):
                target = os.path.abspath('var/www/flaskapps/catalog/static/uploads/images/')
                # target = os.path.join(APP_ROOT, 'static/')
                print(target)
                if not os.path.isdir(target):
                    os.mkdir(target)
                else:
                    print("Couldn't create upload directory: {}".format(target))
                print(request.files.getlist("file"))
                for upload in request.files.getlist("file"):
                    print(upload)
                    print("{} is the file name".format(upload.filename))
                    filename = upload.filename
                    destination = "/".join([target, filename])
                    print ("Accept incoming file:", filename)
                    print ("Save it to:", destination)
                    upload.save(destination)
                    print(destination)
                    edited_manufacturer.up_file = upload.filename
            if request.form['name']:
                edited_manufacturer.name = request.form['name']
            if request.form['description']:
                edited_manufacturer.description = request.form['description']
            sess.add(edited_manufacturer)
            sess.commit()
            return redirect(url_for('u_manufacturer',
                                    manufacturer_id=edited_manufacturer.id))
        else:
            return render_template('manufacturer/manufacturer_edit.html',
                                   manufacturer=edited_manufacturer,
                                   menu_categories=menu_categories,
                                   menu_shops=menu_shops,
                                   menu_manufacturers=menu_manufacturers
                                   )
        pass
    else:
        return redirect(url_for('index'))

@auth.login_required
@rate_limit(limit=30, per=30 * 1)
@app.route('/manufacturer/<int:manufacturer_id>/delete',
           methods=['GET', 'POST'])
def delete_manufacturer(manufacturer_id):
    if 'username' not in login_session:
        return redirect('/login')
    if sess.query(Manufacturer) \
        .filter_by(id=manufacturer_id) \
            .count():
        manufacturer = sess.query(Manufacturer) \
            .filter_by(id=manufacturer_id) \
            .one()
        if manufacturer.user_id != login_session['user_id']:
            return redirect('/login')

        """Menu queries"""
        menu_categories = sess.query(Category) \
            .order_by(Category.id) \
            .all()
        menu_shops = sess.query(Shop) \
            .order_by(Shop.id) \
            .all()
        menu_manufacturers = sess.query(Manufacturer) \
            .order_by(Manufacturer.id) \
            .all()

        if request.method == 'POST':
            sess.delete(manufacturer)
            sess.commit()
            return redirect(url_for('all_manufacturers',
                                    menu_categories=menu_categories,
                                    menu_shops=menu_shops,
                                    menu_manufacturers=menu_manufacturers
                                    ))
        else:
            return render_template(
                'manufacturer/deleteconfirmation_manufacturer.html',
                manufacturer=manufacturer,
                menu_categories=menu_categories,
                menu_shops=menu_shops,
                menu_manufacturers=menu_manufacturers
            )
        pass
    else:
        return redirect(url_for('index'))

"""Login with a provider"""


@rate_limit(limit=30, per=30 * 1)
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(
                json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print("access token received %s " % access_token)

    app_id = json.loads(open('/var/www/flaskapps/catalog/fb_client_secrets.json', 'r')
                        .read())['web']['app_id']
    app_secret = json.loads(
            open('/var/www/flaskapps/catalog/fb_client_secrets.json', 'r')
            .read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/' \
          'access_token?grant_type=fb_exchange_token&' \
          'client_id=%s&' \
          'client_secret=%s&' \
          'fb_exchange_token=%s' % (
              app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print(result)

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')
    print(token)
    url = 'https://graph.facebook.com/v2.8/' \
          'me?access_token=%s&' \
          'fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    print(data)
    print(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?' \
          'access_token=%s&' \
          'redirect=0&' \
          'height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = ' \
              '"width: 300px;' \
              ' height: 300px;' \
              'border-radius: 150px;' \
              '-webkit-border-radius: 150px;' \
              '-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@rate_limit(limit=30, per=30 * 1)
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps(
                'Invalid state parameter.'),
                401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets(
                '/var/www/flaskapps/catalog/client_secrets.json',
                scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
                json.dumps(
                        'Failed to upgrade the authorization code.'),
                401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?'
           'access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(
                json.dumps(result.get('error')),
                500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
                json.dumps(
                        "Token's user ID doesn't match given user ID."),
                401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
                json.dumps(
                        "Token's client ID does not match app's."),
                401)
        print("Token's client ID does not match apps.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
                'Current user is already connected.'),
                200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {
        'access_token': credentials.access_token,
        'alt':          'json'
    }
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = '<section class="form-section">'
    output += '<div class="form-container">'
    output += '<h1 class="form-header">Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '"style = "width: 300px;' \
              'height: 300px;border-radius: 150px' \
              '-webkit-border-radius: 150px;' \
              '-moz-border-radius: 150px;"> ' \
              '</section>' \
              '</div>'
    flash("you are now logged in as %s"
          % login_session['username'])
    print("done!")
    return output


@rate_limit(limit=30, per=30 * 1)
@app.route('/clientOAuth')
def start():
    return render_template('clientOAuth.html')


@rate_limit(limit=30, per=30 * 1)
@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
    # STEP 1 - Parse the auth code
    auth_code = request.json.get('auth_code')
    print "Step 1 - Complete, received auth code %s" % auth_code
    if provider == 'google':
        # STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets(
                    '/var/www/flaskapps/catalog/client_secrets.json', scope=''
            )
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps(
                    'Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = (
            'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
            % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'
        print "Step 2 Complete! Access Token : %s " % credentials.access_token

        # Find User or make a new one

        # Get user info
        h = httplib2.Http()
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)

        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']

        # see if user exists, if it doesn't make a new one
        user = sess.query(User).filter_by(email=email).first()
        if not user:
            user = User(username=name, picture=picture, email=email)
            sess.add(user)
            sess.commit()

        # STEP 4 - Make token
        token = user.generate_auth_token(600)

        # STEP 5 - Send back token to the client
        return jsonify({'token': token.decode('ascii')})

    # return jsonify({'token': token.decode('ascii'), 'duration': 600})
    else:
        return 'Unrecognized Provider'


@rate_limit(limit=30, per=30 * 1)
@app.route('/disconnect')
def disconnect():
    """Disconnect based on provider"""
    if 'username' in login_session:
        if login_session['provider'] == 'google':
            del login_session['credentials']
            del login_session['gplus_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            credentials = login_session.get('credentials')
            if credentials is None:
                redirect('/index')
            access_token = credentials
            url = 'https://accounts.google.com/o/oauth2/' \
                  'revoke?token=%s' \
                  % access_token
            h = httplib2.Http()
            result = h.request(url, 'GET')[0]
            response = make_response(json.dumps(
                    'Successfully disconnected.'),
                    200)
            response.headers['Content-Type'] = 'application/json'
            redirect('/')
        if login_session['provider'] == 'facebook':
            facebook_id = login_session['facebook_id']
            # The access token must be included to successfully logout
            access_token = login_session['access_token']
            url = 'https://graph.facebook.com/%s/permissions?' \
                  'access_token=%s' \
                  % (facebook_id, access_token)
            h = httplib2.Http()
            del login_session['facebook_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['user_id']
            del login_session['provider']
            result = h.request(url, 'DELETE')[1]
        flash("You have successfully been logged out.")
        return redirect(url_for('index'))
    else:
        flash("You were not logged in")
        return redirect(url_for('show_login'))

# Standard convention. Call if this is run as the main module.
if __name__ == '__main__':
    app.secret_key = json.loads(
            open('/var/www/flaskapps/catalog/client_secrets.json', 'r')
            .read())['web']['client_secret']
    app.run(host='0.0.0.0', port=8080, debug=True)
