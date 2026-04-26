import tkinter as tk
from tkinter import messagebox, simpledialog
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from backend.library_system import LibrarySystem, User, Admin, AdvancedUser, Client, Book
from security.utils import sanitize_input
from cryptography.fernet import Fernet

class SessionManager:
    def __init__(self, library):
        self.library = library
        self.session_file = 'data/session_token.dat'
        self.key = self.library.aes_key

    def create_session(self, username, remember_me=False):
        import time
        expiry = int(time.time()) + (30 * 24 * 60 * 60) if remember_me else int(time.time()) + (24 * 60 * 60)  # 30 days or 1 day
        token_data = f"{username}:{expiry}"
        cipher = Fernet(self.key)
        token = cipher.encrypt(token_data.encode()).decode()
        with open(self.session_file, 'w') as f:
            f.write(token)

    def load_session(self):
        if not os.path.exists(self.session_file):
            return None
        try:
            import time
            with open(self.session_file, 'r') as f:
                token = f.read().strip()
            cipher = Fernet(self.key)
            token_data = cipher.decrypt(token.encode()).decode()
            username, expiry = token_data.split(':')
            if int(time.time()) > int(expiry):
                self.clear_session()
                return None
            user = self.library.users.get(username)
            return user
        except:
            self.clear_session()
            return None

    def clear_session(self):
        if os.path.exists(self.session_file):
            os.remove(self.session_file)

class LibraryGUI:
    def __init__(self, root):
        self.root = root
        self.root.title('SafeLibrary')
        self.root.geometry('800x600')
        self.root.configure(bg='#2A1D15')

        self.library = LibrarySystem()
        self.session_manager = SessionManager(self.library)
        self.current_user = None
        self.selected_book = None
        self.filtered_books = []

        auto_user = self.session_manager.load_session()
        if auto_user:
            self.current_user = auto_user
            self.create_dashboard_screen()
        else:
            self.create_login_screen()

    def create_login_screen(self):
        self.clear_screen()

        tk.Label(self.root, text='SafeLibrary', font=('Arial', 26, 'bold'), bg='#2A1D15', fg='#D4AF37').pack(pady=24)

        tk.Label(self.root, text='Login to your library', font=('Arial', 14), bg='#2A1D15', fg='#FDFDFA').pack(pady=(0, 16))

        self.email_entry = tk.Entry(self.root, width=32, bg='#A8866E', fg='#1A1A1A', highlightthickness=0)
        self.email_entry.pack(pady=(0, 10))
        self.email_entry.insert(0, 'Email')
        self.email_entry.bind('<FocusIn>', lambda e: self._clear_placeholder(self.email_entry, 'Email'))

        password_frame = tk.Frame(self.root, bg='#2A1D15')
        password_frame.pack(pady=(0, 10))
        self.password_entry = tk.Entry(password_frame, show='*', width=27, bg='#A8866E', fg='#1A1A1A', highlightthickness=0)
        self.password_entry.pack(side='left')
        self.password_entry.insert(0, 'Password')
        self.password_entry.bind('<FocusIn>', lambda e: self._clear_placeholder(self.password_entry, 'Password', hide=True))
        self.eye_button = tk.Button(password_frame, text='👁', command=self.toggle_password, bg='#A8866E', fg='#1A1A1A', bd=0)
        self.eye_button.pack(side='left', padx=(4, 0))

        self.remember_var = tk.BooleanVar()
        tk.Checkbutton(self.root, text='Remember Me', variable=self.remember_var, bg='#2A1D15', fg='#FDFDFA', selectcolor='#A8866E').pack(pady=4)

        tk.Button(self.root, text='Login', command=self.login, bg='#A8866E', fg='#D4AF37', width=24, height=1).pack(pady=10)
        tk.Button(self.root, text='Continue with Google', command=self.google_login, bg='#D4AF37', fg='#2A1D15', width=24, height=1).pack(pady=6)
        tk.Button(self.root, text='Create Account', command=self.create_register_screen, bg='#A8866E', fg='#FDFDFA', width=24, height=1).pack(pady=6)

        self.forgot_button = tk.Button(self.root, text='Forgot Password', command=self.forgot_password, bg='#A8866E', fg='#FDFDFA', width=24, height=1)
        self.forgot_button.pack(pady=10)
        self.forgot_button.pack_forget()

    def _clear_placeholder(self, widget, placeholder, hide=False):
        if widget.get() == placeholder:
            widget.delete(0, tk.END)
            if hide:
                widget.config(show='*')

    def create_register_screen(self):
        self.clear_screen()
        tk.Label(self.root, text='Create your account', font=('Arial', 24), bg='#2A1D15', fg='#D4AF37').pack(pady=20)

        self.reg_name_entry = tk.Entry(self.root, width=32, bg='#A8866E', fg='#1A1A1A')
        self.reg_name_entry.pack(pady=8)
        self.reg_name_entry.insert(0, 'Full Name')
        self.reg_name_entry.bind('<FocusIn>', lambda e: self._clear_placeholder(self.reg_name_entry, 'Full Name'))

        self.reg_email_entry = tk.Entry(self.root, width=32, bg='#A8866E', fg='#1A1A1A')
        self.reg_email_entry.pack(pady=8)
        self.reg_email_entry.insert(0, 'Email')
        self.reg_email_entry.bind('<FocusIn>', lambda e: self._clear_placeholder(self.reg_email_entry, 'Email'))

        password_frame = tk.Frame(self.root, bg='#2A1D15')
        password_frame.pack(pady=8)
        self.reg_password_entry = tk.Entry(password_frame, show='*', width=27, bg='#A8866E', fg='#1A1A1A')
        self.reg_password_entry.pack(side='left')
        self.reg_password_entry.insert(0, 'Password')
        self.reg_password_entry.bind('<FocusIn>', lambda e: self._clear_placeholder(self.reg_password_entry, 'Password', hide=True))
        reg_eye_button = tk.Button(password_frame, text='👁', command=lambda: self._toggle_register_password(reg_eye_button), bg='#A8866E', fg='#1A1A1A', bd=0)
        reg_eye_button.pack(side='left', padx=(4, 0))

        tk.Button(self.root, text='Sign Up', command=self.register, bg='#D4AF37', fg='#2A1D15', width=24, height=1).pack(pady=10)
        tk.Button(self.root, text='Back to Login', command=self.create_login_screen, bg='#A8866E', fg='#FDFDFA', width=24, height=1).pack(pady=6)

    def _toggle_register_password(self, button):
        if self.reg_password_entry.cget('show') == '*':
            self.reg_password_entry.config(show='')
            button.config(text='🙈')
        else:
            self.reg_password_entry.config(show='*')
            button.config(text='👁')

    def toggle_password(self):
        if self.password_entry.cget('show') == '*':
            self.password_entry.config(show='')
            self.eye_button.config(text='🙈')
        else:
            self.password_entry.config(show='*')
            self.eye_button.config(text='👁')

    def google_login(self):
        google_window = tk.Toplevel(self.root)
        google_window.title('Choose Google Account')
        google_window.geometry('400x300')
        google_window.configure(bg='#2A1D15')
        
        tk.Label(google_window, text='Choose an account', font=('Arial', 16), bg='#2A1D15', fg='#D4AF37').pack(pady=20)
        
        for account in self.library.google_accounts:
            btn = tk.Button(google_window, text=f"{account['name']}\n{account['email']}", 
                          command=lambda acc=account: self.select_google_account(acc, google_window),
                          bg='#A8866E', fg='#1A1A1A', width=30, height=2)
            btn.pack(pady=5)

    def select_google_account(self, account, window):
        window.destroy()
        email = account['email']
        name = account['name']
        
        user = self.library.google_login(email)
        if user:
            self.current_user = user
            self.session_manager.create_session(email, self.remember_var.get())
            self.create_dashboard_screen()
        else:
            messagebox.showerror('Google Login Failed', 'Could not authenticate with Google')

    def login(self):
        email = sanitize_input(self.email_entry.get().strip())
        if email == 'Email':
            email = ''
        password = self.password_entry.get().strip()
        if password == 'Password':
            password = ''
        try:
            user = self.library.login(email, password)
            if not user:
                raise ValueError('Invalid credentials')
            self.current_user = user
            self.session_manager.create_session(email, self.remember_var.get())
            self.create_dashboard_screen()
        except ValueError as e:
            messagebox.showerror('Login failed', str(e))
            if email and email in self.library.users:
                self.forgot_button.pack(pady=5)

    def register(self):
        full_name = sanitize_input(self.reg_name_entry.get().strip())
        email = sanitize_input(self.reg_email_entry.get().strip())
        password = self.reg_password_entry.get().strip()
        if password == 'Password':
            password = ''

        if full_name and email and password:
            try:
                profile_data = {
                    'full_name': full_name,
                    'email': email,
                    'favorites': [],
                    'phone': '',
                    'address': '',
                    'profile_picture_path': 'No image selected',
                }
                base_user = User.create_user(email, password, 'client', profile_data)
                user = Client(base_user.username, base_user.password_hash, base_user.salt, base_user.role, base_user.encrypted_personal_data)
                user.register(self.library)
                messagebox.showinfo('Success', 'Registered successfully. Please login.')
                self.create_login_screen()
            except Exception as e:
                messagebox.showerror('Registration failed', str(e))
        else:
            messagebox.showerror('Registration failed', 'Please fill in all fields.')

    def create_dashboard_screen(self):
        self.clear_screen()
        self.root.geometry('800x600')

        header_frame = tk.Frame(self.root, bg='#A8866E', bd=2, relief='solid')
        header_frame.pack(fill='x', pady=5)
        tk.Label(header_frame, text='SafeLibrary', font=('Arial', 20), bg='#A8866E', fg='#2A1D15').pack(side='left', padx=10)

        self.ensure_nav_bar()

        self.content_frame = tk.Frame(self.root, bg='#2A1D15')
        self.content_frame.pack(fill='both', expand=True)

        self.show_home()

    def create_nav_button(self, title, command):
        tk.Button(self.nav_frame, text=title, command=command, bg='#A8866E', fg='#D4AF37').pack(side='left', padx=5)

    def ensure_nav_bar(self):
        if hasattr(self, 'nav_frame') and self.nav_frame.winfo_exists():
            return
        self.nav_frame = tk.Frame(self.root, bg='#A8866E')
        self.nav_frame.pack(fill='x', side='bottom')
        self.create_nav_button('🏠 Home', self.show_home)
        self.create_nav_button('💛 Favorites', self.show_favorites)
        self.create_nav_button('👤 Profile', self.show_profile)
        tk.Button(self.nav_frame, text='Logout', command=self.logout, bg='#C06014', fg='#FDFDFA').pack(side='right', padx=10)

    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def show_home(self):
        self.ensure_nav_bar()
        self.clear_content()
        self.library.log_operation('navigate', {'username': self.current_user.username, 'screen': 'home'})

        search_frame = tk.Frame(self.content_frame, bg='#2A1D15')
        search_frame.pack(fill='x', padx=10, pady=10)

        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, width=40, bg='#A8866E', fg='#2A1D15')
        search_entry.pack(side='left', padx=(0, 10))
        search_entry.insert(0, 'Search by Title or ISBN...')
        search_entry.bind('<FocusIn>', lambda e: self._clear_search_placeholder(search_entry, 'Search by Title or ISBN...'))
        search_entry.bind('<FocusOut>', lambda e: self._restore_search_placeholder(search_entry, 'Search by Title or ISBN...'))
        search_entry.bind('<KeyRelease>', lambda e: self.update_book_list())

        self.genre_var = tk.StringVar(value='All Genres')
        genres = ['All Genres', 'Fiction', 'Crime', 'History', 'Drama', 'Children\'s', 'Fantasy', 'Technology', 'Science']
        genre_menu = tk.OptionMenu(search_frame, self.genre_var, *genres, command=lambda v: self.update_book_list())
        genre_menu.pack(side='left', padx=(0, 10))

        self.author_var = tk.StringVar(value='All Authors')
        authors = ['All Authors'] + sorted(set(book.author for book in self.library.books.values()))
        author_menu = tk.OptionMenu(search_frame, self.author_var, *authors, command=lambda v: self.update_book_list())
        author_menu.pack(side='left', padx=(0, 10))

        self.available_var = tk.BooleanVar()
        avail_cb = tk.Checkbutton(search_frame, text='Available Only', variable=self.available_var, bg='#2A1D15', fg='#FDFDFA', command=self.update_book_list)
        avail_cb.pack(side='left')

        self.book_frame = tk.Frame(self.content_frame, bg='#2A1D15')
        self.book_frame.pack(fill='both', expand=True, padx=10, pady=10)

        self.update_book_list()

    def _clear_search_placeholder(self, widget, placeholder):
        if widget.get() == placeholder:
            widget.delete(0, tk.END)

    def _restore_search_placeholder(self, widget, placeholder):
        if not widget.get().strip():
            widget.insert(0, placeholder)

    def update_book_list(self):
        criteria = {
            'title': self.search_var.get().strip(),
            'genre': self.genre_var.get(),
            'author': self.author_var.get(),
            'status': 'available' if self.available_var.get() else 'all',
        }
        self.filtered_books = self.library.filter_books(criteria)
        self.display_book_grid()

    def toggle_favorite(self, book):
        if self.current_user.has_favorite(book.id):
            self.current_user.remove_favorite(self.library, book.id)
            messagebox.showinfo('Favorites', f'Removed "{book.title}" from favorites')
        else:
            self.current_user.add_favorite(self.library, book.id)
            messagebox.showinfo('Favorites', f'Added "{book.title}" to favorites')
        self.update_book_list()

    def display_book_grid(self):
        for widget in self.book_frame.winfo_children():
            widget.destroy()

        row = 0
        col = 0
        max_col = 3
        for book in self.filtered_books:
            card = tk.Frame(self.book_frame, bg='#A8866E', bd=1, relief='solid', width=200, height=260)
            card.grid(row=row, column=col, padx=10, pady=10)
            card.pack_propagate(False)

            tk.Label(card, text='📖', font=('Arial', 40), bg='#A8866E', fg='#2A1D15').pack(pady=10)

            tk.Label(card, text=book.title, bg='#A8866E', fg='#2A1D15', font=('Arial', 12, 'bold')).pack()
            tk.Label(card, text=book.author, bg='#A8866E', fg='#FDFDFA').pack()

            rating = self.library.get_book_rating(book.id)
            stars = '★' * int(rating) + '☆' * (5 - int(rating))
            tk.Label(card, text=stars, bg='#A8866E', fg='#D4AF37').pack()

            status = 'Available' if book.available else 'Out of Stock'
            status_color = '#A8B5A0' if book.available else '#C19A6B'
            tk.Label(card, text=status, bg='#A8866E', fg=status_color).pack()

            fav_text = '💛' if self.current_user.has_favorite(book.id) else '🤍'
            fav_btn = tk.Button(card, text=fav_text, command=lambda b=book: self.toggle_favorite(b), bg='#A8866E', fg='#D4AF37', bd=0)
            fav_btn.pack(pady=4)

            card.bind('<Button-1>', lambda e, b=book: self.show_book_detail(b))
            for child in card.winfo_children():
                if child is not fav_btn:
                    child.bind('<Button-1>', lambda e, b=book: self.show_book_detail(b))

            col += 1
            if col >= max_col:
                col = 0
                row += 1

    def show_book_detail(self, book):
        self.selected_book = book
        detail_window = tk.Toplevel(self.root)
        detail_window.title('Book Detail')
        detail_window.geometry('600x500')
        detail_window.configure(bg='#2A1D15')

        header_frame = tk.Frame(detail_window, bg='#A8866E')
        header_frame.pack(fill='x')
        tk.Label(header_frame, text='Book Profile', font=('Arial', 16), bg='#A8866E', fg='#2A1D15').pack(side='left', padx=10)
        tk.Button(header_frame, text='X', command=detail_window.destroy, bg='#C06014', fg='#FDFDFA').pack(side='right', padx=10)

        content = tk.Frame(detail_window, bg='#2A1D15')
        content.pack(fill='both', expand=True, padx=20, pady=20)

        tk.Label(content, text='📖', font=('Arial', 60), bg='#2A1D15', fg='#D4AF37').grid(row=0, column=0, rowspan=4, padx=10)

        tk.Label(content, text=book.title, font=('Arial', 18), bg='#2A1D15', fg='#FDFDFA').grid(row=0, column=1, sticky='w')
        tk.Label(content, text=f'Author: {book.author}', bg='#2A1D15', fg='#FDFDFA').grid(row=1, column=1, sticky='w')
        rating = self.library.get_book_rating(book.id)
        stars = '★' * int(rating) + '☆' * (5 - int(rating))
        tk.Label(content, text=f'Rating: {stars} ({rating:.1f}/5)', bg='#2A1D15', fg='#D4AF37').grid(row=2, column=1, sticky='w')
        tk.Label(content, text=f'Available: {book.available_copies}/{book.total_copies}', bg='#2A1D15', fg='#FDFDFA').grid(row=3, column=1, sticky='w')
        tk.Label(content, text=f'Location: {book.location}', bg='#2A1D15', fg='#FDFDFA').grid(row=4, column=1, sticky='w')

        tk.Label(content, text='Description:', bg='#2A1D15', fg='#FDFDFA').grid(row=4, column=0, columnspan=2, sticky='w', pady=(20, 0))
        desc_text = tk.Text(content, height=4, bg='#A8866E', fg='#2A1D15', wrap='word')
        desc_text.insert('1.0', book.description)
        desc_text.config(state='disabled')
        desc_text.grid(row=5, column=0, columnspan=2, sticky='ew', pady=5)

        tk.Label(content, text='Reviews:', bg='#2A1D15', fg='#FDFDFA').grid(row=6, column=0, columnspan=2, sticky='w', pady=(20, 0))
        reviews = self.library.get_book_reviews(book.id)
        review_frame = tk.Frame(content, bg='#2A1D15')
        review_frame.grid(row=7, column=0, columnspan=2, sticky='ew')
        for i, review in enumerate(reviews[:2]):
            tk.Label(review_frame, text=f'{review.username}: {review.comment} ({review.rating}★)', bg='#2A1D15', fg='#FDFDFA', wraplength=500, justify='left').pack(anchor='w', pady=2)

        review_entry = tk.Entry(review_frame, bg='#A8866E', fg='#2A1D15')
        review_entry.pack(fill='x', pady=5)
        tk.Button(review_frame, text='Add Review', command=lambda: self.add_review(detail_window, book, review_entry), bg='#D4AF37', fg='#2A1D15').pack()

        controls = tk.Frame(content, bg='#2A1D15')
        controls.grid(row=8, column=0, columnspan=2, pady=(20, 5))
        tk.Button(controls, text='Reserve (1hr)', command=lambda: self.reserve_book(detail_window, book), bg='#D4AF37', fg='#2A1D15').pack(side='left', padx=5)
        tk.Button(controls, text='Open Preview', command=lambda: self.open_book_preview(book), bg='#A8866E', fg='#2A1A1A').pack(side='left', padx=5)
        fav_label = 'Remove from Favorites' if self.current_user.has_favorite(book.id) else 'Add to Favorites'
        tk.Button(controls, text=fav_label, command=lambda: self.toggle_favorite(book), bg='#A8866E', fg='#2A1A1A').pack(side='left', padx=5)

    def open_book_preview(self, book):
        try:
            preview = self.library.open_book(self.current_user.username, book.id)
            preview_window = tk.Toplevel(self.root)
            preview_window.title(f'Preview - {book.title}')
            preview_window.geometry('600x360')
            preview_window.configure(bg='#2A1D15')
            text_area = tk.Text(preview_window, bg='#A8866E', fg='#2A1D15', wrap='word')
            text_area.insert('1.0', preview)
            text_area.config(state='disabled')
            text_area.pack(fill='both', expand=True, padx=10, pady=10)
        except Exception as e:
            messagebox.showerror('Preview Error', str(e))

    def add_review(self, window, book, entry):
        comment = entry.get().strip()
        if not comment:
            return
        rating = simpledialog.askinteger('Rating', 'Rate 1-5:', minvalue=1, maxvalue=5)
        if rating:
            try:
                self.library.add_review(self.current_user.username, book.id, rating, comment)
                messagebox.showinfo('Review', 'Added')
                window.destroy()
                self.show_book_detail(book)
            except Exception as e:
                messagebox.showerror('Error', str(e))

    def reserve_book(self, window, book):
        try:
            reservation = self.library.reserve_book(self.current_user.username, book.id)
            window.destroy()
            self.update_book_list()
            self.show_reservation_modal(reservation)
        except Exception as e:
            messagebox.showerror('Error', str(e))

    def show_reservation_modal(self, reservation):
        modal = tk.Toplevel(self.root)
        modal.title('Reservation Confirmed')
        modal.geometry('420x220')
        modal.configure(bg='#2A1D15')

        tk.Label(modal, text='Reservation Confirmed', font=('Arial', 18, 'bold'), bg='#2A1D15', fg='#D4AF37').pack(pady=12)
        status_label = tk.Label(modal, text='Generating your reservation number...', font=('Arial', 14), bg='#2A1D15', fg='#FDFDFA')
        status_label.pack(pady=8)

        number_label = tk.Label(modal, text='', font=('Arial', 20, 'bold'), bg='#2A1D15', fg='#D4AF37')
        number_label.pack(pady=8)

        def reveal(count=0):
            if count == 0:
                status_label.config(text='Success! Your reservation number:')
                number_label.config(text=reservation.reservation_id)
                self.root.after(50, lambda: reveal(1))
                return
            if count < 6:
                number_label.config(text=reservation.reservation_id + ' ' + '✨' * count)
                self.root.after(150, lambda: reveal(count + 1))
                return
            tk.Button(modal, text='OK', command=modal.destroy, bg='#A8866E', fg='#2A1D15').pack(pady=10)

        reveal()

    def leave_review(self):
        if not self.selected_book:
            return
        rating = simpledialog.askinteger('Leave Review', 'Rating (1-5):', minvalue=1, maxvalue=5)
        comment = simpledialog.askstring('Leave Review', 'Comment:')
        if rating and comment:
            try:
                self.library.add_review(self.current_user.username, self.selected_book.id, rating, comment)
                messagebox.showinfo('Review', 'Review submitted')
                self.show_book_detail(self.selected_book)
            except Exception as e:
                messagebox.showerror('Review failed', str(e))

    def show_favorites(self):
        self.ensure_nav_bar()
        self.clear_content()
        self.library.log_operation('navigate', {'username': self.current_user.username, 'screen': 'favorites'})

        tk.Label(self.content_frame, text='Favorites', font=('Arial', 18), bg='#2A1D15', fg='#D4AF37').pack(pady=10)

        favorites = self.current_user.get_favorites()
        self.filtered_books = [self.library.books[bid] for bid in favorites if bid in self.library.books]

        self.book_frame = tk.Frame(self.content_frame, bg='#2A1D15')
        self.book_frame.pack(fill='both', expand=True, padx=10, pady=10)

        self.display_book_grid()

    def show_profile(self):
        self.ensure_nav_bar()
        self.clear_content()
        self.library.log_operation('navigate', {'username': self.current_user.username, 'screen': 'profile'})
        tk.Label(self.content_frame, text='Profile', font=('Arial', 18), bg='#2A1D15', fg='#D4AF37').pack(pady=10)

        data = self.current_user.get_personal_data(self.library.aes_key)

        avatar_frame = tk.Frame(self.content_frame, bg='#D4AF37', bd=2, relief='solid', width=100, height=100)
        avatar_frame.pack(pady=10)
        avatar_frame.pack_propagate(False)
        avatar_path = data.get('profile_picture_path', 'No image selected')
        if avatar_path != 'No image selected' and os.path.exists(avatar_path):
            tk.Label(avatar_frame, text='🖼️', font=('Arial', 40), bg='#A8866E', fg='#2A1D15').pack(expand=True)
        else:
            tk.Label(avatar_frame, text='👤', font=('Arial', 40), bg='#A8866E', fg='#2A1D15').pack(expand=True)
        tk.Button(avatar_frame, text='Update', command=self.update_avatar, bg='#A8866E', fg='#2A1D15').pack(side='bottom')

        self.avatar_path_label = tk.Label(self.content_frame, text=f'Avatar: {avatar_path}', bg='#2A1D15', fg='#FDFDFA')
        self.avatar_path_label.pack(pady=(0, 10))

        self.profile_entries = {}
        fields = ['full_name', 'phone', 'address']
        for field in fields:
            frame = tk.Frame(self.content_frame, bg='#2A1D15')
            frame.pack(fill='x', padx=20, pady=5)
            tk.Label(frame, text=f"{field.replace('_', ' ').title()}:", bg='#2A1D15', fg='#FDFDFA', width=10, anchor='w').pack(side='left')
            entry = tk.Entry(frame, bg='#A8866E', fg='#2A1D15')
            entry.insert(0, data.get(field, ''))
            entry.pack(side='left', fill='x', expand=True)
            self.profile_entries[field] = entry

        tk.Button(self.content_frame, text='Save Profile', command=self.save_profile, bg='#D4AF37', fg='#2A1D15').pack(pady=10)
        tk.Button(self.content_frame, text='Log Out', command=self.logout, bg='#C06014', fg='#FDFDFA').pack(pady=10)

        tk.Label(self.content_frame, text='Favorites:', bg='#2A1D15', fg='#D4AF37', font=('Arial', 14)).pack(pady=(20, 5))
        favorites = data.get('favorites', [])
        if favorites:
            for bid in favorites[:5]:  # Show first 5
                book = self.library.books.get(bid)
                if book:
                    tk.Label(self.content_frame, text=f'♥ {book.title} by {book.author}', bg='#2A1D15', fg='#FDFDFA').pack(pady=1)
        else:
            tk.Label(self.content_frame, text='No favorites yet', bg='#2A1D15', fg='#FDFDFA').pack(pady=5)

        tk.Button(self.content_frame, text='My Reservations', command=self.show_my_reservations, bg='#3B2F2F', fg='#D4AF37', bd=2, relief='ridge', font=('Arial', 11, 'bold')).pack(pady=5)
        self.reservation_list_frame = tk.Frame(self.content_frame, bg='#2A1D15')
        self.reservation_list_frame.pack(fill='both', expand=False, padx=20, pady=(10, 0))
        self.render_reservation_list()

        tk.Button(self.content_frame, text='Change Password', command=self.change_password, bg='#D4AF37', fg='#2A1D15').pack(pady=20)

        tk.Label(self.content_frame, text='Account Management', bg='#2A1D15', fg='#C06014').pack(pady=10)
        tk.Button(self.content_frame, text='Delete Personal Info', command=self.delete_personal_info, bg='#A8866E', fg='#FDFDFA').pack(pady=5)
        tk.Button(self.content_frame, text='GDPR Full Delete', command=self.gdpr_delete, bg='#C06014', fg='#FDFDFA').pack(pady=5)

    def save_profile(self):
        data = self.current_user.get_personal_data(self.library.aes_key)
        for field, entry in self.profile_entries.items():
            data[field] = entry.get().strip()
        self.current_user.set_personal_data(data, self.library.aes_key)
        self.library.save_data()
        self.library.log_operation('profile_updated', {'username': self.current_user.username})
        messagebox.showinfo('Success', 'Profile updated')
        self.show_profile()

    def render_reservation_list(self):
        for widget in self.reservation_list_frame.winfo_children():
            widget.destroy()

        reservations = self.library.get_active_reservations(self.current_user.username)
        if not reservations:
            tk.Label(self.reservation_list_frame, text='No active bookings', bg='#2A1D15', fg='#D4AF37', font=('Arial', 12, 'bold')).pack(anchor='w', pady=10)
            return

        for reservation in reservations:
            title = reservation.book_title or self.library.books.get(reservation.book_id, Book('', '', '', '', '', 0, 0, '')).title
            remaining = reservation.time_remaining()
            minutes = int(remaining.total_seconds() // 60)
            time_text = 'Expires in: <1 minute' if minutes < 1 else f'Expires in: {minutes} minutes'

            entry_frame = tk.Frame(self.reservation_list_frame, bg='#3B2F2F', bd=1, relief='ridge')
            entry_frame.pack(fill='x', pady=6)
            tk.Label(entry_frame, text=f'Book Title: {title}', bg='#3B2F2F', fg='#D4AF37', font=('Arial', 12, 'bold')).pack(anchor='w', padx=10, pady=(8, 0))
            tk.Label(entry_frame, text=time_text, bg='#3B2F2F', fg='#FDFDFA', font=('Arial', 11)).pack(anchor='w', padx=10, pady=(4, 0))
            tk.Label(entry_frame, text=f'Code: {reservation.reservation_id}', bg='#3B2F2F', fg='#D4AF37', font=('Arial', 11, 'bold')).pack(anchor='w', padx=10, pady=(4, 8))

    def show_my_reservations(self):
        modal = tk.Toplevel(self.root)
        modal.title('Active Bookings')
        modal.geometry('520x360')
        modal.configure(bg='#2A1D15')

        tk.Label(modal, text='Active Bookings', font=('Arial', 16, 'bold'), bg='#2A1D15', fg='#D4AF37').pack(pady=10)

        reservation_list_frame = tk.Frame(modal, bg='#2A1D15')
        reservation_list_frame.pack(fill='both', expand=True, padx=12, pady=8)

        reservations = self.library.get_active_reservations(self.current_user.username)
        if not reservations:
            tk.Label(reservation_list_frame, text='No active bookings', bg='#2A1D15', fg='#D4AF37', font=('Arial', 13, 'bold')).pack(anchor='w', pady=12)
        else:
            for reservation in reservations:
                title = reservation.book_title or self.library.books.get(reservation.book_id, Book('', '', '', '', '', 0, 0, '')).title
                remaining = reservation.time_remaining()
                minutes = int(remaining.total_seconds() // 60)
                time_text = 'Expires in: <1 minute' if minutes < 1 else f'Expires in: {minutes} minutes'

                entry_frame = tk.Frame(reservation_list_frame, bg='#3B2F2F', bd=2, relief='ridge')
                entry_frame.pack(fill='x', pady=6)
                tk.Label(entry_frame, text=f'Book Title: {title}', bg='#3B2F2F', fg='#D4AF37', font=('Arial', 12, 'bold')).pack(anchor='w', padx=10, pady=(8, 0))
                tk.Label(entry_frame, text=time_text, bg='#3B2F2F', fg='#FDFDFA', font=('Arial', 11)).pack(anchor='w', padx=10, pady=(4, 0))
                tk.Label(entry_frame, text=f'Code: {reservation.reservation_id}', bg='#3B2F2F', fg='#D4AF37', font=('Arial', 11, 'bold')).pack(anchor='w', padx=10, pady=(4, 8))

        tk.Button(modal, text='Close', command=modal.destroy, bg='#A8866E', fg='#2A1D15').pack(pady=10)

    def leave_review(self):
        if not self.selected_book:
            return
        rating = simpledialog.askinteger('Leave Review', 'Rating (1-5):', minvalue=1, maxvalue=5)
        comment = simpledialog.askstring('Leave Review', 'Comment:')
        if rating and comment:
            try:
                self.library.add_review(self.current_user.username, self.selected_book.id, rating, comment)
                messagebox.showinfo('Review', 'Review submitted')
                self.show_book_detail(self.selected_book)
            except Exception as e:
                messagebox.showerror('Review failed', str(e))

    def update_avatar(self):
        from tkinter import filedialog
        file_path = filedialog.askopenfilename(filetypes=[('Image files', '*.png *.jpg *.jpeg *.gif *.bmp')])
        if file_path:
            try:
                if not os.path.exists(file_path):
                    raise ValueError('Selected avatar file does not exist')
                self.current_user.update_avatar(self.library, file_path)
                self.library.log_operation('avatar_updated', {'username': self.current_user.username, 'avatar_path': file_path})
                messagebox.showinfo('Success', 'Avatar updated')
                self.show_profile()  # Refresh
            except Exception as e:
                messagebox.showerror('Error', str(e))

    def change_password(self):
        old_pass = simpledialog.askstring('Change Password', 'Current Password:', show='*')
        new_pass = simpledialog.askstring('Change Password', 'New Password:', show='*')
        if old_pass and new_pass:
            try:
                self.library.update_password(self.current_user.username, old_pass, new_pass)
                messagebox.showinfo('Success', 'Password changed')
            except Exception as e:
                messagebox.showerror('Error', str(e))

    def delete_personal_info(self):
        if messagebox.askyesno('Confirm', 'Delete personal info?'):
            favorites = self.current_user.get_personal_data(self.library.aes_key).get('favorites', [])
            self.current_user.set_personal_data({'favorites': favorites}, self.library.aes_key)
            self.library.save_data()
            self.library.log_operation('delete_personal_info', {'username': self.current_user.username})
            messagebox.showinfo('Deleted', 'Personal info deleted')
            self.show_profile()

    def gdpr_delete(self):
        if messagebox.askyesno('Confirm', 'Full GDPR delete? This is irreversible.'):
            self.library.delete_user_data(self.current_user.username)
            messagebox.showinfo('Deleted', 'Account fully deleted')
            self.logout()

    def forgot_password(self):
        username = simpledialog.askstring('Forgot Password', 'Username:')
        email = simpledialog.askstring('Forgot Password', 'Email:')
        new_password = simpledialog.askstring('Forgot Password', 'New Password:', show='*')
        if username and email and new_password:
            try:
                self.library.reset_password_by_email(username.strip(), email.strip(), new_password.strip())
                messagebox.showinfo('Success', 'Password updated via email verification')
                self.forgot_button.pack_forget()
            except Exception as e:
                messagebox.showerror('Error', str(e))

    def logout(self):
        if self.current_user:
            self.library.log_operation('logout', {'username': self.current_user.username})
        self.session_manager.clear_session()
        self.current_user = None
        self.selected_book = None
        self.filtered_books = []
        self.create_login_screen()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()


if __name__ == '__main__':
    root = tk.Tk()
    app = LibraryGUI(root)
    root.mainloop()
