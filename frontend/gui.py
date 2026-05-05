import os
import sys
from functools import wraps
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '_vendor'))
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from backend.library_system import LibrarySystem, User
from security.utils import sanitize_input, validate_email

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'change-me-secret')

library = LibrarySystem()

@app.context_processor
def inject_request():
    return {'request': request}


def current_user():
    username = session.get('username')
    if username:
        user = library.users.get(username)
        if user:
            user.set_encryption_key(library.aes_key)
            return user
    return None


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if current_user() is None:
            flash('Будь ласка, увійдіть у свій обліковий запис', 'warning')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped_view


def resolve_asset_url(path):
    if path.startswith('assets/'):
        return url_for('assets', path=path[len('assets/'):])
    return path


@app.route('/')
def index():
    if current_user():
        return redirect(url_for('home'))
    return redirect(url_for('login'))


@app.route('/assets/<path:path>')
def assets(path):
    return send_from_directory(os.path.join(BASE_DIR, 'assets'), path)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = sanitize_input(request.form.get('email', '').strip().lower())
        password = request.form.get('password', '')
        google_login = request.form.get('google') == '1'

        try:
            if google_login:
                user = library.google_login(email)
                if not user:
                    raise ValueError('Google account not found')
            else:
                user = library.login(email, password)
            session['username'] = user.username
            flash('Успішний вхід', 'success')
            return redirect(url_for('home'))
        except Exception as exc:
            flash(str(exc), 'danger')

    return render_template('login.html', google_accounts=library.google_accounts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = sanitize_input(request.form.get('full_name', '').strip())
        email = sanitize_input(request.form.get('email', '').strip().lower())
        password = request.form.get('password', '')

        if not full_name or not email or not password:
            flash('Заповніть усі поля', 'danger')
            return redirect(url_for('register'))

        if not validate_email(email):
            flash('Недійсна електронна адреса', 'danger')
            return redirect(url_for('register'))

        try:
            profile_data = {
                'full_name': full_name,
                'email': email,
                'favorites': [],
                'phone': '',
                'address': '',
                'profile_picture_path': 'No image selected',
            }
            user = User.create_user(email, password, 'client', profile_data)
            user.register(library)
            session['username'] = user.username
            flash('Реєстрація успішна! Оберіть аватар.', 'success')
            return redirect(url_for('onboarding'))
        except Exception as exc:
            flash(str(exc), 'danger')

    return render_template('register.html')


@app.route('/onboarding', methods=['GET', 'POST'])
@login_required
def onboarding():
    user = current_user()
    if request.method == 'POST':
        avatar_type = request.form.get('avatar_type')
        if avatar_type == 'upload':
            # Handle upload
            if 'avatar' in request.files:
                file = request.files['avatar']
                if file.filename:
                    # Save file
                    avatars_dir = os.path.join(BASE_DIR, 'assets', 'avatars')
                    os.makedirs(avatars_dir, exist_ok=True)
                    avatar_filename = f"{user.username}_avatar{os.path.splitext(file.filename)[1]}"
                    avatar_path = os.path.join(avatars_dir, avatar_filename)
                    file.save(avatar_path)
                    user.update_avatar(library, avatar_path)
        elif avatar_type == 'default':
            selected = request.form.get('default_avatar')
            if selected:
                default_path = f'assets/avatars/defaults/{selected}.png'
                user.update_avatar(library, default_path)
        return redirect(url_for('home'))
    
    return render_template('onboarding.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Ви вийшли з системи', 'info')
    return redirect(url_for('login'))


@app.route('/home')
@login_required
def home():
    user = current_user()
    criteria = {
        'title': request.args.get('title', ''),
        'author': request.args.get('author', ''),
        'genre': request.args.get('genre', ''),
        'status': request.args.get('status', 'all'),
    }
    books = library.filter_books(criteria)
    profile_name = user.get_personal_data(library.aes_key).get('full_name', user.username)
    return render_template(
        'home.html',
        user=user,
        books=books,
        criteria=criteria,
        profile_name=profile_name,
        resolve_asset_url=resolve_asset_url,
    )


@app.route('/favorites')
@login_required
def favorites():
    user = current_user()
    books = [library.books[book_id] for book_id in user.get_favorites() if book_id in library.books]
    return render_template('favorites.html', user=user, books=books, resolve_asset_url=resolve_asset_url)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user()
    profile_data = user.get_personal_data(library.aes_key)
    reservations = library.get_active_reservations(user.username)

    if request.method == 'POST':
        old_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        if not old_password or not new_password:
            flash('Заповніть обидва поля для зміни пароля', 'danger')
        else:
            try:
                library.update_password(user.username, old_password, new_password)
                flash('Пароль оновлено', 'success')
            except Exception as exc:
                flash(str(exc), 'danger')
        return redirect(url_for('profile'))

    return render_template(
        'profile.html',
        user=user,
        profile_data=profile_data,
        reservations=reservations,
        resolve_asset_url=resolve_asset_url,
    )


@app.route('/book/<book_id>', methods=['GET', 'POST'])
@login_required
def book_detail(book_id):
    user = current_user()
    book = library.books.get(book_id)
    if not book:
        flash('Книга не знайдена', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        rating = request.form.get('rating')
        comment = request.form.get('comment', '')
        try:
            library.add_review(user.username, book_id, rating, comment)
            flash('Оцінка додана', 'success')
            return redirect(url_for('book_detail', book_id=book_id))
        except Exception as exc:
            flash(str(exc), 'danger')

    reviews = library.get_book_reviews(book_id)
    preview_text = None
    preview_error = None
    try:
        preview_text = library.open_book(user.username, book_id)
    except Exception as exc:
        preview_error = str(exc)

    return render_template(
        'book_detail.html',
        user=user,
        book=book,
        reviews=reviews,
        rating=library.get_book_rating(book_id),
        resolve_asset_url=resolve_asset_url,
        preview_text=preview_text,
        preview_error=preview_error,
    )


@app.route('/reserve/<book_id>')
@login_required
def reserve(book_id):
    user = current_user()
    try:
        reservation = library.reserve_book(user.username, book_id)
        flash('Книга заброньована', 'success')
        # Instead of redirect, show confirmation with timer
        return render_template('reserve_success.html', reservation=reservation, user=user, resolve_asset_url=resolve_asset_url)
    except Exception as exc:
        flash(str(exc), 'danger')
        return redirect(request.referrer or url_for('home'))


@app.route('/favorite/<book_id>', methods=['POST'])
@login_required
def toggle_favorite(book_id):
    user = current_user()
    try:
        is_favorite = user.has_favorite(book_id)
        if is_favorite:
            user.remove_favorite(library, book_id)
            message = 'Видалено з обраного'
        else:
            user.add_favorite(library, book_id)
            message = 'Додано до обраного'
        return {'success': True, 'is_favorite': not is_favorite, 'message': message}
    except Exception as exc:
        return {'success': False, 'message': str(exc)}, 400


@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    user = current_user()
    if 'avatar' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('profile'))
    
    file = request.files['avatar']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('profile'))
    
    try:
        # Save the file
        import os
        avatars_dir = os.path.join(BASE_DIR, 'assets', 'avatars')
        os.makedirs(avatars_dir, exist_ok=True)
        avatar_filename = f"{user.username}_avatar{os.path.splitext(file.filename)[1]}"
        avatar_path = os.path.join(avatars_dir, avatar_filename)
        file.save(avatar_path)
        
        # Update user profile
        user.update_avatar(library, avatar_path)
        flash('Avatar updated', 'success')
    except Exception as exc:
        flash(str(exc), 'danger')
    
    return redirect(url_for('profile'))


@app.route('/delete_avatar', methods=['POST'])
@login_required
def delete_avatar():
    user = current_user()
    try:
        data = user.get_personal_data(library.aes_key)
        data['profile_picture_path'] = 'No image selected'
        user.set_personal_data(data, library.aes_key)
        library.save_data()
        library.log_operation('avatar_deleted', {'username': user.username})
        return {'success': True}
    except Exception as exc:
        return {'success': False, 'message': str(exc)}, 400


@app.route('/redeem', methods=['POST'])
@login_required
def redeem():
    user = current_user()
    data = request.get_json()
    cost = data.get('cost')
    reward = data.get('reward')
    try:
        if user.redeem_points(cost, library):
            library.log_operation('reward_redeemed', {'username': user.username, 'reward': reward, 'cost': cost})
            return {'success': True}
        else:
            return {'success': False, 'message': 'Недостатньо SafePoints'}
    except Exception as exc:
        return {'success': False, 'message': str(exc)}, 400


@app.route('/gdpr_wipe', methods=['POST'])
@login_required
def gdpr_wipe():
    user = current_user()
    confirm = request.form.get('confirm', '').strip().lower()
    if confirm != 'delete':
        flash('Confirmation required', 'danger')
        return redirect(url_for('profile'))
    
    try:
        library.delete_user_data(user.username)
        session.pop('username', None)
        flash('All user data deleted', 'info')
        return redirect(url_for('login'))
    except Exception as exc:
        flash(str(exc), 'danger')
        return redirect(url_for('profile'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
