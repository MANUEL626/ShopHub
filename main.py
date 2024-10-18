from flask import Flask, render_template, request, url_for, redirect, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from function import get_secret_key, verify_password, verify_name, verify_mail, verify_user
from base64 import b64encode, b64decode


app = Flask(__name__)

app.secret_key = get_secret_key()

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gty.db'
# 'postgresql://postgres:{}@localhost:5432/{}'.format( 'MANUEL', 'ALC')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.Text(50), nullable=False)
    mail = db.Column(db.Text, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    isAdmin = db.Column(db.Boolean, nullable=False)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    category = db.Column(db.String, nullable=False)
    subcategory = db.Column(db.String, nullable=False)
    price = db.Column(db.Float, nullable=False)
    picture = db.Column(db.Text, nullable=False)

    def get_picture_url(self):
        return f"data:image/jpeg;base64,{self.picture}"

    def get_item_url(self):
        return f"/item/{self.id}"


class FavoriteItem(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('favorite_items', lazy=True))
    item = db.relationship('Item', backref=db.backref('favorited_by', lazy=True))

    __table_args__ = (db.UniqueConstraint('user_id', 'item_id', name='_user_item_uc'),)


with app.app_context():
    db.create_all()


@app.before_request
def create_admin():
    query = User.query.filter_by(isAdmin=True).first()
    if not query:
        user = User(
            username='administrator',
            mail='fynoox@gmail.com',
            password='BlackLaw1@',
            isAdmin=True
        )
        try:
            db.session.add(user)
            db.session.commit()
        except Exception:
            db.session.rollback()


@app.route('/')
def index():
    items = []
    categories = db.session.query(Item.category).distinct()
    for item_type in categories:
        type_items = Item.query.filter_by(category=item_type[0]).limit(5).all()
        items.extend(type_items)
    return render_template('index.html', items=items, title='Home', categories=categories)


@app.route('/category/<string:category_name>')
def category(category_name):
    categories = db.session.query(Item.category).distinct()
    items = Item.query.filter_by(category=category_name).all()
    if 'user_id' in session:
        user = User.query.filter_by(id=session['user_id']).first()
        return render_template('items.html', items=items, title=category_name, categories=categories, user=user)
    else:
        return render_template('items.html', items=items, title=category_name, categories=categories)


@app.route('/item/<int:item_id>')
def view_item(item_id):
    item = Item.query.get_or_404(item_id)
    return render_template('item.html', item=item)


@app.route('/search')
def search():
    items = []
    categories = db.session.query(Item.category).distinct()
    if request.method == "GET":
        q = request.args.get('search', '')
        if q != '':
            items = Item.query.filter(Item.name.ilike(f'%{q}%')).all()
    return render_template('search.html', items=items, categories=categories)


@app.route('/login', methods=['POST', 'GET'])
def login():
    categories = db.session.query(Item.category).distinct()
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        query = User.query.filter_by(username=username, password=password).first()

        if query:
            if not query.isAdmin:
                session["user_id"] = query.id
                session["logged"] = True
                flash(category='success', message='you are logged')
                return redirect(url_for('account'))
            else:
                session["admin_id"] = query.id
                session["admin_logged"] = True
                session["user_id"] = query.id
                session["logged"] = True
                return redirect(url_for('admin'))

        else:
            flash(category='error', message='incorrect identifiers')

    return render_template('login.html', title='Login', categories=categories)


@app.route('/register', methods=['POST', 'GET'])
def register():
    categories = db.session.query(Item.category).distinct()
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['mail']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        existing_user = User.query.filter_by(username=username).first()
        existing_mail = User.query.filter_by(mail=email).first()
        if verify_password(password, confirm_password) and verify_user(existing_user) and verify_name(username) and verify_mail(existing_mail):
            user = User(
                username=username,
                mail=email,
                password=password,
                isAdmin=False
            )
            try:
                db.session.add(user)
                db.session.commit()
                flash(category='success', message='account create successfully')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                print(e)
                flash(category='error', message='account creation was not successful')

    return render_template('register.html', title='Register', categories=categories)


@app.route('/account', methods=['POST', 'GET'])
def account():
    categories = db.session.query(Item.category).distinct()
    if 'user_id' not in session:
        return redirect(url_for('login'))
    elif 'user_id':
        user = User.query.filter_by(id=session['user_id']).first()
        if request.method == 'POST':
            if 'username' in request.form:
                username = request.form['username']
                exiting_name = User.query.filter_by(username=username).first()
                if verify_name(exiting_name):
                    try:
                        user.username = username
                        db.session.commit()
                        flash(category='success', message='Username updated')
                        return redirect(url_for('account'))
                    except Exception as e:
                        db.session.rollback()
                        print(e)
                        flash(category='error', message='error while editing')
            elif 'mail' in request.form:
                email = request.form['mail']
                exiting_mail = User.query.filter_by(mail=email).first()
                if verify_mail(exiting_mail):
                    try:
                        user.mail = email
                        db.session.commit()
                        flash(category='success', message='Email updated')
                        return redirect(url_for('account'))
                    except Exception as e:
                        db.session.rollback()
                        print(e)
                        flash(category='error', message='error while editing')
            elif 'password' and 'confirm_password' in request.form:
                password = request.form['password']
                confirm_password = request.form['confirm_password']
                if verify_password(password, confirm_password):
                    try:
                        user.password = password
                        db.session.commit()
                        flash(category='success', message='Password updated')
                        return redirect(url_for('account'))
                    except Exception as e:
                        db.session.rollback()
                        print(e)
                        flash(category='error', message='error while editing')
    return render_template('account.html', user=user, categories=categories)


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.pop('user_id', None)
    session.pop('admin_id', None)
    session.pop('logged', None)
    session.pop('admin_logged', None)
    flash(category='success', message='You have been logged out')
    return redirect(url_for('login'))


@app.route('/user.delete', methods=['POST', 'GET'])
def user_delete():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Vérifier si l'utilisateur est un administrateur et essaie de supprimer son propre compte
    if 'admin_id' in session and session['user_id'] == session['admin_id']:
        flash(category='error', message='You can\'t delete this account')
        return redirect(url_for('account'))

    # Vérifier si l'utilisateur peut être supprimé
    if session['user_id'] != session.get('admin_id'):
        user = User.query.get(session['user_id'])
        if user:
            db.session.delete(user)
            db.session.commit()
            session.pop('user_id')  # Déconnexion de l'utilisateur
            flash(category='success', message='Account deleted successfully')
            return redirect(url_for('index'))

    return redirect(url_for('index'))



@app.route('/remove_flash_message', methods=['POST'])
def remove_flash_message():
    message_to_remove = request.json.get('message')
    category_to_remove = request.json.get('category')

    flashed_messages = session.get('_flashes', [])

    session['_flashes'] = [msg for msg in flashed_messages if msg != (category_to_remove, message_to_remove)]

    return jsonify(success=True)


@app.route('/add_to_favorites/<int:item_id>', methods=['POST', 'GET'])
def add_to_favorites(item_id):
    existing_favorite = FavoriteItem.query.filter_by(user_id=session['user_id'], item_id=item_id).first()
    if not existing_favorite:
        favorite = FavoriteItem(user_id=session['user_id'], item_id=item_id)
        db.session.add(favorite)
        db.session.commit()
    return redirect(request.referrer or url_for('index'))


@app.route('/remove_from_favorites/<int:item_id>', methods=['POST', 'GET'])
def remove_from_favorites(item_id):
    favorite = FavoriteItem.query.filter_by(user_id=session['user_id'], item_id=item_id).first()
    if favorite:
        db.session.delete(favorite)
        db.session.commit()
    return redirect(request.referrer or url_for('index'))


# Admin


@app.route('/gty.admin')
def admin():
    if 'admin_id' not in session:
        return redirect(url_for('login'))
    items = Item.query.all()
    return render_template('admin.html', items=items, title='admin')


@app.route('/gty.manage/<int:item_id>', methods=['GET', 'POST'])
def manage(item_id):
    if 'admin_id' not in session:
        return redirect(url_for('login'))
    item = Item.query.filter_by(id=item_id).first()
    if request.method == 'POST':
        if 'name' in request.form:
            name = request.form['name']
            try:
                item.name = name
                db.session.commit()
                flash(category='success', message='')
                return redirect(url_for('manage'))
            except Exception:
                db.session.rollback()
                flash(category='error', message='')

        if 'price' in request.form:
            price = request.form['type']
            try:
                item.price = price
                db.session.commit()
                flash(category='success', message='')
                return redirect(url_for('manage'))
            except Exception:
                db.session.rollback()
                flash(category='error', message='')

        if 'category' in request.form:
            category = request.form['category']
            try:
                item.category = category
                db.session.commit()
                flash(category='success', message='')
                return redirect(url_for('manage'))
            except Exception:
                db.session.rollback()
                flash(category='error', message='')

        if 'subcategory' in request.form:
            subcategory = request.form['subcategory']
            try:
                item.subcategory = subcategory
                db.session.commit()
                flash(category='success', message='')
                return redirect(url_for('manage'))
            except Exception:
                db.session.rollback()
                flash(category='error', message='')

        if 'picture' in request.files:
            picture = request.files.get('picture').read()
            picture = b64encode(picture).decode('utf-8')
            try:
                item.picture = picture
                db.session.commit()
                flash(category='success', message='')
                return redirect(url_for('manage'))
            except Exception:
                db.session.rollback()
                flash(category='error', message='')
    return render_template('manage.html', item=item)


@app.route('/gty.admin/post', methods=['GET', 'POST'])
def post():
    if 'admin_id' not in session:
        return redirect(url_for('login'))
    elif 'admin_id':
        if request.method == 'POST':
            name = request.form['name']
            category = request.form['category']
            subcategory = request.form['subcategory']
            price = float(request.form['price'])
            picture = request.files.get('picture').read()
            picture = b64encode(picture).decode('utf-8')
            if price > 0:
                item = Item(
                    name=name,
                    category=category,
                    subcategory=subcategory,
                    price=price,
                    picture=picture
                )
                try:
                    db.session.add(item)
                    db.session.commit()
                    flash(category='success', message='Item created successfully')
                    return redirect(url_for('admin'))
                except Exception as e:
                    db.session.rollback()
                    print(e)
                    flash(category='error', message='Item creation was not successful')
            else:
                flash(category='error', message='The price must be positive')

    return render_template('post.html', title='Post')


@app.route('/gty.admin/delete.item/<int:item_id>', methods=['POST', 'GET'])
def delete_item(item_id):
    if 'admin_id' not in session:
        return redirect(url_for('login'))
    try:
        item = Item.query.get_or_404(item_id)
        print(item.name)
        FavoriteItem.query.filter_by(item_id=item_id).delete()
        db.session.delete(item)
        db.session.commit()
        flash(category='success', message='Item deleted')
    except Exception as e:
        print(e)
        db.session.rollback()
        flash(category='error', message='error while deleting')
    return redirect(url_for('admin'))


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html', error='error'), 404


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
