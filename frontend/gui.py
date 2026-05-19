import os
import sys
from functools import wraps
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '_vendor'))
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from backend.library_system import LibrarySystem, User, Book


def load_dotenv(dotenv_path):
    if not os.path.exists(dotenv_path):
        return
    with open(dotenv_path, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and ((value[0] == value[-1] == '"') or (value[0] == value[-1] == "'")):
                value = value[1:-1]
            if key and key not in os.environ:
                os.environ[key] = value

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))

from security.utils import sanitize_input, validate_email
from security.utils import validate_phone, validate_date

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'change-me-secret')

library = LibrarySystem(base_path=os.environ.get('LIBRARY_BASE_PATH'))

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
        relative_path = path[len('assets/'):]
        asset_path = os.path.join(library.base_path, 'assets', relative_path)
        if not os.path.exists(asset_path):
            relative_path = 'covers/placeholder.jpg'
        return url_for('assets', path=relative_path)
    return path


@app.route('/')
def index():
    if current_user():
        return redirect(url_for('home'))
    return redirect(url_for('login'))


@app.route('/assets/<path:path>')
def assets(path):
    return send_from_directory(os.path.join(library.base_path, 'assets'), path)


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
        phone = sanitize_input(request.form.get('phone', '').strip())
        birth_date = sanitize_input(request.form.get('birth_date', '').strip())
        address = sanitize_input(request.form.get('address', '').strip())
        city = sanitize_input(request.form.get('city', '').strip())

        if not full_name or not email or not password:
            flash('Заповніть усі поля', 'danger')
            return redirect(url_for('register'))

        if not validate_email(email):
            flash('Недійсна електронна адреса', 'danger')
            return redirect(url_for('register'))

        if phone and not validate_phone(phone):
            flash('Недійсний номер телефону', 'danger')
            return redirect(url_for('register'))
        if birth_date and not validate_date(birth_date):
            flash('Недійсна дата народження', 'danger')
            return redirect(url_for('register'))

        try:
            profile_data = {
                'full_name': full_name,
                'email': email,
                'favorites': [],
                'phone': phone,
                'address': address,
                'city': city,
                'birth_date': birth_date,
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
                    avatars_dir = os.path.join(library.base_path, 'assets', 'avatars')
                    os.makedirs(avatars_dir, exist_ok=True)
                    avatar_filename = f"{user.username}_avatar{os.path.splitext(file.filename)[1]}"
                    avatar_path = os.path.join(avatars_dir, avatar_filename)
                    file.save(avatar_path)
                    user.update_avatar(library, avatar_path)
        elif avatar_type == 'default':
            selected = request.form.get('default_avatar')
            if selected:
                default_path = os.path.join('assets', 'avatars', 'defaults', f'{selected}.png')
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
    # Show all reservations (active and expired) so user can return them manually
    reservations = [r for r in library.reservations if r.username == user.username]

    if request.method == 'POST':
        # Determine if this is profile update or password change
        if 'current_password' in request.form or 'new_password' in request.form:
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
        else:
            # profile data update
            full_name = sanitize_input(request.form.get('full_name', '').strip())
            phone = sanitize_input(request.form.get('phone', '').strip())
            address = sanitize_input(request.form.get('address', '').strip())
            city = sanitize_input(request.form.get('city', '').strip())
            birth_date = sanitize_input(request.form.get('birth_date', '').strip())
            if not full_name:
                flash('ПІБ є обов\'язковим', 'danger')
                return redirect(url_for('profile'))
            if phone and not validate_phone(phone):
                flash('Недійсний номер телефону', 'danger')
                return redirect(url_for('profile'))
            if birth_date and not validate_date(birth_date):
                flash('Недійсна дата народження', 'danger')
                return redirect(url_for('profile'))
            try:
                data = user.get_personal_data(library.aes_key)
                data['full_name'] = full_name
                data['phone'] = phone
                data['address'] = address
                data['city'] = city
                data['birth_date'] = birth_date
                user.set_personal_data(data, library.aes_key)
                library.save_data()
                library.log_operation('profile_updated', {'username': user.username})
                flash('Профіль оновлено', 'success')
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


@app.route('/users')
@login_required
def users_list():
    user = current_user()
    if not user or user.role not in {'admin', 'advanced'}:
        flash('Доступ заборонено', 'danger')
        return redirect(url_for('home'))
    users = user.view_all_users(library)
    return render_template('admin_users.html', user=user, users=users, resolve_asset_url=resolve_asset_url, is_admin=(user.role == 'admin'), is_advanced=(user.role == 'advanced'))

@app.route('/admin/users')
@login_required
def admin_users():
    user = current_user()
    if not user or user.role != 'admin':
        flash('Доступ заборонено', 'danger')
        return redirect(url_for('home'))
    users = user.view_all_users(library)
    return render_template('admin_users.html', user=user, users=users, resolve_asset_url=resolve_asset_url, is_admin=True, is_advanced=(user.role == 'advanced'))


@app.route('/send_reminder/<username>/<reservation_id>', methods=['POST'])
@login_required
def send_reminder(username, reservation_id):
    user = current_user()
    if not user or user.role != 'advanced':
        flash('Доступ заборонено', 'danger')
        return redirect(url_for('home'))
    try:
        sent = library.send_overdue_email(reservation_id, sender_user=user)
        if sent:
            flash('Нагадування надіслано користувачу', 'success')
        else:
            flash('Неможливо надіслати лист: або ця книга ще не прострочена, або для неї вже надсилали нагадування протягом 24 годин', 'warning')
    except Exception as exc:
        flash(str(exc), 'danger')
    return redirect(url_for('users_list'))


@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def admin_add_user():
    admin = current_user()
    if not admin or admin.role != 'admin':
        flash('Доступ заборонено', 'danger')
        return redirect(url_for('home'))
    if request.method == 'POST':
        full_name = sanitize_input(request.form.get('full_name', '').strip())
        email = sanitize_input(request.form.get('email', '').strip().lower())
        password = request.form.get('password', '')
        role = sanitize_input(request.form.get('role', 'client'))
        phone = sanitize_input(request.form.get('phone', '').strip())
        birth_date = sanitize_input(request.form.get('birth_date', '').strip())
        address = sanitize_input(request.form.get('address', '').strip())
        city = sanitize_input(request.form.get('city', '').strip())
        if not full_name or not email or not password:
            flash('Заповніть обов\'язкові поля', 'danger')
            return redirect(url_for('admin_add_user'))
        if phone and not validate_phone(phone):
            flash('Недійсний телефон', 'danger')
            return redirect(url_for('admin_add_user'))
        if birth_date and not validate_date(birth_date):
            flash('Недійсна дата', 'danger')
            return redirect(url_for('admin_add_user'))
        try:
            profile_data = {
                'full_name': full_name,
                'email': email,
                'phone': phone,
                'address': address,
                'city': city,
                'birth_date': birth_date,
                'favorites': [],
                'profile_picture_path': 'No image selected',
            }
            new_user = User.create_user(email, password, role, profile_data)
            admin.add_user(library, new_user)
            flash('Користувача створено', 'success')
            return redirect(url_for('admin_users'))
        except Exception as exc:
            flash(str(exc), 'danger')
            return redirect(url_for('admin_add_user'))
    return render_template('admin_add_user.html', user=admin)


@app.route('/admin/delete_user/<path:email>', methods=['POST'])
@login_required
def admin_delete_user(email):
    admin = current_user()
    if not admin or admin.role != 'admin':
        flash('Доступ заборонено', 'danger')
        return redirect(url_for('home'))
    # Prevent admin from deleting self
    if email == admin.username:
        flash('Не можна видалити себе', 'danger')
        return redirect(url_for('admin_users'))
    try:
        library.delete_user_data(email)
        flash('Користувача видалено', 'success')
    except Exception as exc:
        flash(str(exc), 'danger')
    return redirect(url_for('admin_users'))


@app.route('/admin/books')
@login_required
def admin_books():
    user = current_user()
    if not user or user.role != 'admin':
        flash('Доступ заборонено', 'danger')
        return redirect(url_for('home'))
    return render_template('admin_books.html', user=user, books=library.books.values(), resolve_asset_url=resolve_asset_url)


@app.route('/admin/add_book', methods=['GET', 'POST'])
@login_required
def admin_add_book():
    admin = current_user()
    if not admin or admin.role != 'admin':
        flash('Доступ заборонено', 'danger')
        return redirect(url_for('home'))
    if request.method == 'POST':
        book_id = sanitize_input(request.form.get('id', '').strip())
        title = sanitize_input(request.form.get('title', '').strip())
        author = sanitize_input(request.form.get('author', '').strip())
        genre = sanitize_input(request.form.get('genre', '').strip())
        year = request.form.get('year', '').strip()
        total_copies = request.form.get('total_copies', '').strip()
        available_copies = request.form.get('available_copies', '').strip()
        location = sanitize_input(request.form.get('location', '').strip())
        description = sanitize_input(request.form.get('description', '').strip())
        rating = request.form.get('rating', '').strip()
        avatar_book = sanitize_input(request.form.get('avatar_book', '').strip())
        file_content_path = sanitize_input(request.form.get('file_content_path', '').strip())
        if not book_id or not title or not author or not genre:
            flash('Заповніть обов’язкові поля книги', 'danger')
            return redirect(url_for('admin_add_book'))
        try:
            book = Book(
                book_id,
                title,
                author,
                genre,
                int(year) if year.isdigit() else 2024,
                int(total_copies) if total_copies.isdigit() else 1,
                int(available_copies) if available_copies.isdigit() else int(total_copies) if total_copies.isdigit() else 1,
                location or 'Unknown branch',
                description or 'No description available',
                float(rating) if rating.replace('.', '', 1).isdigit() else 3.0,
                avatar_book=avatar_book or f'assets/covers/{genre}_{book_id}.jpg',
                file_content_path=file_content_path or f'assets/library/{genre}_{book_id}.txt',
            )
            library.add_book(book)
            flash('Книгу додано', 'success')
            return redirect(url_for('admin_books'))
        except Exception as exc:
            flash(str(exc), 'danger')
            return redirect(url_for('admin_add_book'))
    return render_template('admin_book_form.html', action='add', book=None, user=admin)


@app.route('/admin/edit_book/<book_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_book(book_id):
    admin = current_user()
    if not admin or admin.role != 'admin':
        flash('Доступ заборонено', 'danger')
        return redirect(url_for('home'))
    book = library.books.get(book_id)
    if not book:
        flash('Книга не знайдена', 'danger')
        return redirect(url_for('admin_books'))
    if request.method == 'POST':
        title = sanitize_input(request.form.get('title', '').strip())
        author = sanitize_input(request.form.get('author', '').strip())
        genre = sanitize_input(request.form.get('genre', '').strip())
        year = request.form.get('year', '').strip()
        total_copies = request.form.get('total_copies', '').strip()
        available_copies = request.form.get('available_copies', '').strip()
        location = sanitize_input(request.form.get('location', '').strip())
        description = sanitize_input(request.form.get('description', '').strip())
        rating = request.form.get('rating', '').strip()
        avatar_book = sanitize_input(request.form.get('avatar_book', '').strip())
        file_content_path = sanitize_input(request.form.get('file_content_path', '').strip())
        try:
            updated = library.update_book(
                book_id,
                title=title or book.title,
                author=author or book.author,
                genre=genre or book.genre,
                year=int(year) if year.isdigit() else book.year,
                total_copies=int(total_copies) if total_copies.isdigit() else book.total_copies,
                available_copies=int(available_copies) if available_copies.isdigit() else book.available_copies,
                location=location or book.location,
                description=description or book.description,
                rating=float(rating) if rating.replace('.', '', 1).isdigit() else book.rating,
                avatar_book=avatar_book or getattr(book, 'avatar_book', None) or getattr(book, 'cover_front_path', None) or getattr(book, 'cover_back_path', None),
                file_content_path=file_content_path or book.file_content_path,
            )
            flash('Книгу оновлено', 'success')
            return redirect(url_for('admin_books'))
        except Exception as exc:
            flash(str(exc), 'danger')
            return redirect(url_for('admin_edit_book', book_id=book_id))
    return render_template('admin_book_form.html', action='edit', book=book, user=admin)


@app.route('/admin/delete_book/<book_id>', methods=['POST'])
@login_required
def admin_delete_book(book_id):
    admin = current_user()
    if not admin or admin.role != 'admin':
        flash('Доступ заборонено', 'danger')
        return redirect(url_for('home'))
    try:
        library.delete_book(book_id)
        flash('Книгу видалено', 'success')
    except Exception as exc:
        flash(str(exc), 'danger')
    return redirect(url_for('admin_books'))


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


@app.route('/reserve/<book_id>', methods=['GET', 'POST'])
@login_required
def reserve(book_id):
    user = current_user()
    if request.method == 'POST':
        duration = request.form.get('duration', '1')
        unit = request.form.get('unit', 'days')
        try:
            duration_val = int(duration)
        except Exception:
            duration_val = 1
        unit_val = (unit or 'days').lower()
        try:
            reservation = library.reserve_book(user.username, book_id, duration=duration_val, unit=unit_val)
            flash('Книга заброньована', 'success')
            return render_template('reserve_success.html', reservation=reservation, user=user, resolve_asset_url=resolve_asset_url)
        except Exception as exc:
            flash(str(exc), 'danger')
            return redirect(request.referrer or url_for('home'))
    else:
        # Maintain backward compatibility: allow GET to create a default reservation
        try:
            reservation = library.reserve_book(user.username, book_id)
            flash('Книга заброньована', 'success')
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
        avatars_dir = os.path.join(library.base_path, 'assets', 'avatars')
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


@app.route('/return/<reservation_id>', methods=['POST'])
@login_required
def return_reservation(reservation_id):
    user = current_user()
    try:
        library.return_reservation(user.username, reservation_id=reservation_id)
        flash('Книга повернена', 'success')
    except Exception as exc:
        flash(str(exc), 'danger')
    return redirect(url_for('profile'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
