import hashlib
import json
import datetime
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from security.utils import hash_password, verify_password, encrypt_data, decrypt_data, validate_email, validate_phone, validate_date, sanitize_input


def json_line_encode(data):
    return json.dumps(data, ensure_ascii=False)


def json_line_decode(line):
    return json.loads(line)


class User:
    """Base class for all users."""

    def __init__(self, username, password_hash, salt, role, profile_data_or_encrypted):
        self.username = username
        self.password_hash = password_hash
        self.salt = salt
        self.role = role
        self.encryption_key = None
        self.failed_attempts = 0
        self.lockout_until = None
        if isinstance(profile_data_or_encrypted, dict):
            self.profile_data = profile_data_or_encrypted
            self.encrypted_personal_data = ''
        else:
            self.encrypted_personal_data = profile_data_or_encrypted
            self.profile_data = None  # Will be set when key is available

    def set_encryption_key(self, key):
        self.encryption_key = key

    def authenticate(self, password):
        """Authenticate a user by verifying the hashed password."""
        return verify_password(password, self.password_hash, self.salt)

    def get_personal_data(self, key=None):
        """Decrypt and return personal data."""
        if self.profile_data is not None:
            return self.profile_data
        if self.encrypted_personal_data:
            key = key or self.encryption_key
            if not key:
                raise ValueError('Encryption key required')
            self.profile_data = decrypt_data(self.encrypted_personal_data, key)
            return self.profile_data
        return {}

    def set_personal_data(self, data, key=None):
        """Validate and encrypt personal data."""
        key = key or self.encryption_key
        if not key:
            raise ValueError('Encryption key required')
        if 'email' in data and not validate_email(data['email']):
            raise ValueError('Invalid email')
        if 'phone' in data and data.get('phone') and not validate_phone(data['phone']):
            raise ValueError('Invalid phone')
        if 'birth_date' in data and data.get('birth_date') and not validate_date(data['birth_date']):
            raise ValueError('Invalid birth date')
        self.profile_data = data
        self.encrypted_personal_data = encrypt_data(data, key)

    def is_locked(self):
        if self.lockout_until:
            unlock_time = datetime.datetime.fromisoformat(self.lockout_until)
            if datetime.datetime.now() < unlock_time:
                return True
            self.failed_attempts = 0
            self.lockout_until = None
        return False

    def record_failed_attempt(self):
        self.failed_attempts += 1
        if self.failed_attempts >= 3:
            self.lockout_until = (datetime.datetime.now() + datetime.timedelta(seconds=30)).isoformat()

    def reset_lockout(self):
        self.failed_attempts = 0
        self.lockout_until = None

    def get_favorites(self):
        """Return the user's favorite book IDs."""
        data = self.get_personal_data()
        return data.get('favorites', [])

    def set_favorites(self, favorites):
        """Save favorites into encrypted personal data."""
        data = self.get_personal_data()
        data['favorites'] = favorites
        self.set_personal_data(data)

    def has_favorite(self, book_id):
        """Return whether the book is in favorites."""
        return book_id in self.get_favorites()

    def add_favorite(self, library, book_id):
        """Add a book to favorites."""
        favorites = self.get_favorites()
        if book_id not in favorites:
            favorites.append(book_id)
            self.set_favorites(favorites)
            library.save_data()
            library.log_operation('favorite_added', {'username': self.username, 'book_id': book_id})

    def remove_favorite(self, library, book_id):
        """Remove a book from favorites."""
        favorites = self.get_favorites()
        if book_id in favorites:
            favorites.remove(book_id)
            self.set_favorites(favorites)
            library.save_data()
            library.log_operation('favorite_removed', {'username': self.username, 'book_id': book_id})

    def register(self, library):
        """Register the user and persist the encrypted profile."""
        self.set_personal_data(self.profile_data, library.aes_key)
        library.users[self.username] = self
        library.save_data()
        library.log_operation(
            'user_registered',
            {
                'username': self.username,
                'role': self.role,
            },
        )

    def view_all_users(self, library):
        raise PermissionError('Access denied')

    def view_orders(self, library):
        raise PermissionError('Access denied')

    def update_avatar(self, library, image_path):
        """Update the user's avatar by copying the image to assets/avatars/."""
        if not os.path.exists(image_path):
            raise ValueError('Image file does not exist')
        
        avatars_dir = 'assets/avatars'
        os.makedirs(avatars_dir, exist_ok=True)
        
        import shutil
        avatar_filename = f"{self.username}_avatar{os.path.splitext(image_path)[1]}"
        avatar_path = os.path.join(avatars_dir, avatar_filename)
        shutil.copy2(image_path, avatar_path)
        
        data = self.get_personal_data(library.aes_key)
        data['profile_picture_path'] = avatar_path
        self.set_personal_data(data, library.aes_key)
        library.save_data()
        library.log_operation('avatar_updated', {'username': self.username})

    @staticmethod
    def create_user(username, password, role, personal_data):
        """Create a new user with salted hash and encrypted personal data."""
        role = role.lower().strip()
        if role not in {'admin', 'advanced', 'client'}:
            raise ValueError('Role must be admin, advanced, or client')

        if 'email' not in personal_data or not validate_email(personal_data['email']):
            raise ValueError('Valid email is required')

        if 'phone' in personal_data and personal_data.get('phone') and not validate_phone(personal_data['phone']):
            raise ValueError('Invalid phone')

        if 'birth_date' in personal_data and personal_data.get('birth_date') and not validate_date(personal_data['birth_date']):
            raise ValueError('Invalid birth date')

        profile_data = dict(personal_data)
        profile_data.setdefault('favorites', [])
        profile_data.setdefault('profile_picture_path', 'No image selected')
        profile_data.setdefault('phone', '')
        profile_data.setdefault('address', '')

        hashed, salt = hash_password(password)
        if role == 'admin':
            return Admin(username, hashed, salt, role, profile_data)
        if role == 'advanced':
            return AdvancedUser(username, hashed, salt, role, profile_data)
        return Client(username, hashed, salt, role, profile_data)


class Admin(User):
    def view_all_users(self, library):
        if self.role != 'admin':
            raise PermissionError('Access denied')
        return library.users

    def add_user(self, library, user):
        if self.role != 'admin':
            raise PermissionError('Access denied')
        user.register(library)
        library.log_operation('user_added', {'username': user.username, 'role': user.role})


class AdvancedUser(User):
    def view_orders(self, library):
        if self.role != 'advanced':
            raise PermissionError('Access denied')
        return library.reservations

    def send_reminder(self, username, message):
        print(f'SMS to {username}: {message}')


class Client(User):
    def borrow_book(self, library, book_id):
        return library.reserve_book(self.username, book_id)


class Book:
    def __init__(
        self,
        id,
        title,
        author,
        genre,
        year=2023,
        total_copies=1,
        available_copies=1,
        location='Unknown branch',
        description='No description available',
        rating=3.0,
        cover_path='assets/covers/placeholder.jpg',
        file_content_path='assets/library/placeholder.txt',
    ):
        self.id = id
        self.title = title
        self.author = author
        self.genre = genre
        self.year = int(year)
        self.total_copies = int(total_copies)
        self.available_copies = int(available_copies)
        self.location = location
        self.description = description
        self.rating = float(rating)
        self.cover_path = cover_path
        self.file_content_path = file_content_path

    @property
    def available(self):
        return self.available_copies > 0

    def to_record(self):
        return {
            'id': self.id,
            'title': self.title,
            'author': self.author,
            'genre': self.genre,
            'year': self.year,
            'total_copies': self.total_copies,
            'available_copies': self.available_copies,
            'location': self.location,
            'description': self.description,
            'rating': self.rating,
            'cover_path': self.cover_path,
            'file_content_path': self.file_content_path,
        }

    @classmethod
    def from_record(cls, data):
        genre = data.get('genre', 'unknown').replace(' ', '_').lower()
        book_id = data['id']
        default_cover = f'assets/covers/{genre}_{book_id}.jpg'
        default_file = f'assets/library/{genre}_{book_id}.txt'
        cover_path = data.get('cover_path') or default_cover
        file_content_path = data.get('file_content_path') or default_file
        if 'placeholder' in str(cover_path):
            cover_path = default_cover
        if 'placeholder' in str(file_content_path):
            file_content_path = default_file
        return cls(
            data['id'],
            data['title'],
            data['author'],
            data['genre'],
            data.get('year', 2023),
            data.get('total_copies', 1),
            data.get('available_copies', 1),
            data.get('location', 'Unknown branch'),
            data.get('description', 'No description available'),
            data.get('rating', 3.0),
            cover_path,
            file_content_path,
        )


class Review:
    def __init__(self, username, book_id, rating, comment, timestamp=None):
        self.username = username
        self.book_id = book_id
        self.rating = int(rating)
        self.comment = comment
        self.timestamp = timestamp or datetime.datetime.now().isoformat()

    def to_record(self):
        return {
            'username': self.username,
            'book_id': self.book_id,
            'rating': self.rating,
            'comment': self.comment,
            'timestamp': self.timestamp,
        }

    @classmethod
    def from_record(cls, data):
        return cls(data['username'], data['book_id'], data['rating'], data['comment'], data['timestamp'])


class Reservation:
    def __init__(self, username, book_id, book_title, start_time, expiry_time, reservation_id):
        self.username = username
        self.book_id = book_id
        self.book_title = book_title
        self.start_time = start_time
        self.expiry_time = expiry_time
        self.reservation_id = reservation_id

    def is_active(self):
        return datetime.datetime.fromisoformat(self.expiry_time) > datetime.datetime.now()

    def time_remaining(self):
        expiry = datetime.datetime.fromisoformat(self.expiry_time)
        remaining = expiry - datetime.datetime.now()
        return max(datetime.timedelta(0), remaining)

    def to_record(self):
        return {
            'username': self.username,
            'book_id': self.book_id,
            'book_title': self.book_title,
            'start_time': self.start_time,
            'expiry_time': self.expiry_time,
            'reservation_id': self.reservation_id,
        }

    @classmethod
    def from_record(cls, data):
        return cls(
            data['username'],
            data['book_id'],
            data.get('book_title', ''),
            data['start_time'],
            data.get('expiry_time', data.get('expire_time', '')),
            data.get('reservation_id', 'UNKNOWN')
        )


class LibrarySystem:
    def __init__(self):
        self.users = {}
        self.books = {}
        self.reviews = []
        self.reservations = []
        self.aes_key = None
        self.google_accounts = [
            {'email': 'sofia.lviv@gmail.com', 'name': 'Sofia Lviv'},
            {'email': 'sonya.test@gmail.com', 'name': 'Sonya Test'},
            {'email': 'user.example@gmail.com', 'name': 'User Example'}
        ]
        self.load_aes_key()
        self.reservation_system = ReservationSystem(self)
        self.load_data()

    def load_aes_key(self):
        key_path = 'data/profile_vault.key'
        if os.path.exists(key_path):
            with open(key_path, 'r') as f:
                self.aes_key = f.read().strip()
        else:
            from cryptography.fernet import Fernet
            self.aes_key = Fernet.generate_key().decode()
            with open(key_path, 'w') as f:
                f.write(self.aes_key)

    def create_user_instance(self, username, password_hash, salt, role, encrypted_personal_data, failed_attempts=0, lockout_until=None):
        if role == 'admin':
            user = Admin(username, password_hash, salt, role, encrypted_personal_data)
        elif role == 'advanced':
            user = AdvancedUser(username, password_hash, salt, role, encrypted_personal_data)
        elif role == 'client':
            user = Client(username, password_hash, salt, role, encrypted_personal_data)
        else:
            user = User(username, password_hash, salt, role, encrypted_personal_data)
        user.set_encryption_key(self.aes_key)
        user.failed_attempts = int(failed_attempts or 0)
        user.lockout_until = lockout_until
        return user

    def create_book_instance(self, record):
        return Book.from_record(record)

    def load_data(self):
        if not os.path.exists('data/auth_vault.txt') and os.path.exists('data/system.log'):
            self.recover_from_log()
            return

        self.users = {}
        self.books = {}
        self.reviews = []
        self.reservations = []

        if os.path.exists('data/auth_vault.txt'):
            with open('data/auth_vault.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    record = json_line_decode(line)
                    user = self.create_user_instance(
                        record['username'],
                        bytes.fromhex(record['password_hash']),
                        bytes.fromhex(record['salt']),
                        record['role'],
                        record.get('encrypted_personal_data', ''),
                        record.get('failed_attempts', 0),
                        record.get('lockout_until', None),
                    )
                    self.users[record['username']] = user

        if os.path.exists('data/profile_vault.txt'):
            with open('data/profile_vault.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    record = json_line_decode(line)
                    if record['username'] in self.users:
                        self.users[record['username']].encrypted_personal_data = record['encrypted_personal_data']

        if os.path.exists('data/books.txt'):
            with open('data/books.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    record = json_line_decode(line)
                    book = self.create_book_instance(record)
                    self.books[book.id] = book

        if os.path.exists('data/reviews.txt'):
            with open('data/reviews.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    record = json_line_decode(line)
                    review = Review.from_record(record)
                    self.reviews.append(review)

        if os.path.exists('data/reservations.txt'):
            with open('data/reservations.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    record = json_line_decode(line)
                    reservation = Reservation.from_record(record)
                    if not reservation.book_title:
                        book = self.books.get(reservation.book_id)
                        reservation.book_title = book.title if book else 'Unknown Title'
                    self.reservations.append(reservation)

        self.cleanup_expired_reservations()
        if not self.books:
            self._seed_sample_books()

    def _seed_sample_books(self):
        sample_books = [
            Book('1', 'The Lord of the Rings', 'J.R.R. Tolkien', 'fantasy', 1954, 5, 5, 'Lviv Central Branch', 'Epic fantasy adventure in Middle-earth.', 4.8),
            Book('2', 'The Hobbit', 'J.R.R. Tolkien', 'fantasy', 1937, 4, 4, 'Lviv Central Branch', 'A hobbit\'s unexpected journey.', 4.7),
            Book('3', 'Harry Potter and the Philosopher\'s Stone', 'J.K. Rowling', 'fantasy', 1997, 6, 6, 'West Branch', 'A young wizard\'s first year at Hogwarts.', 4.9),
            Book('4', 'The Chronicles of Narnia', 'C.S. Lewis', 'fantasy', 1950, 3, 3, 'North Branch', 'Magical adventures in Narnia.', 4.6),
            Book('5', 'His Dark Materials', 'Philip Pullman', 'fantasy', 1995, 4, 4, 'South Branch', 'Parallel universes and daemons.', 4.5),
            Book('6', 'The Name of the Wind', 'Patrick Rothfuss', 'fantasy', 2007, 3, 3, 'Hrushevsky Branch', 'The story of the legendary Kvothe.', 4.8),
            Book('7', 'American Gods', 'Neil Gaiman', 'fantasy', 2001, 4, 4, 'Lviv Central Branch', 'Shadow Moon\'s battle between old and new gods.', 4.4),
            Book('8', 'The Lies of Locke Lamora', 'Scott Lynch', 'fantasy', 2006, 3, 3, 'West Branch', 'A con artist in a richly detailed fantasy world.', 4.7),
            Book('9', 'Mistborn', 'Brandon Sanderson', 'fantasy', 2006, 4, 4, 'North Branch', 'A heist in a world of Allomancy.', 4.6),
            Book('10', 'The Priory of the Orange Tree', 'Samantha Shannon', 'fantasy', 2019, 3, 3, 'South Branch', 'Dragons, queens, and ancient prophecies.', 4.5),
            
            Book('11', 'Murder on the Orient Express', 'Agatha Christie', 'crime', 1934, 4, 4, 'Lviv Central Branch', 'Hercule Poirot solves a murder on a train.', 4.6),
            Book('12', 'The Murder of Roger Ackroyd', 'Agatha Christie', 'crime', 1926, 3, 3, 'Shevchenko Branch', 'Poirot investigates in a quiet English village.', 4.5),
            Book('13', 'And Then There Were None', 'Agatha Christie', 'crime', 1939, 5, 5, 'North Branch', 'Ten strangers trapped on an island.', 4.7),
            Book('14', 'The No. 1 Ladies\' Detective Agency', 'Alexander McCall Smith', 'crime', 1998, 3, 3, 'South Branch', 'Precious Ramotswe, Botswana\'s first female detective.', 4.4),
            Book('15', 'The Cuckoo\'s Calling', 'Robert Galbraith', 'crime', 2013, 4, 4, 'East Branch', 'Cormoran Strike investigates a supermodel\'s death.', 4.3),
            Book('16', 'The Girl with the Dragon Tattoo', 'Stieg Larsson', 'crime', 2005, 4, 4, 'Central Branch', 'Journalist and hacker investigate a disappearance.', 4.5),
            Book('17', 'Gone Girl', 'Gillian Flynn', 'crime', 2012, 5, 5, 'West Branch', 'A missing wife and a media frenzy.', 4.2),
            Book('18', 'The Silence of the Lambs', 'Thomas Harris', 'crime', 1988, 3, 3, 'North Branch', 'Clarice Starling hunts a serial killer.', 4.6),
            Book('19', 'Big Little Lies', 'Liane Moriarty', 'crime', 2014, 4, 4, 'South Branch', 'Secrets and lies in a wealthy suburb.', 4.1),
            Book('20', 'The Dry', 'Jane Harper', 'crime', 2016, 3, 3, 'East Branch', 'A detective returns to his hometown for a murder investigation.', 4.4),
            
            Book('21', 'Sapiens: A Brief History of Humankind', 'Yuval Noah Harari', 'history', 2011, 4, 4, 'Central Branch', 'From apes to cyberspace, the history of our species.', 4.7),
            Book('22', 'Guns, Germs, and Steel', 'Jared Diamond', 'history', 1997, 3, 3, 'West Branch', 'Why some societies succeed and others fail.', 4.5),
            Book('23', 'The Wright Brothers', 'David McCullough', 'history', 2015, 4, 4, 'Franko Branch', 'The story of the airplane inventors.', 4.6),
            Book('24', 'The Diary of a Young Girl', 'Anne Frank', 'history', 1947, 5, 5, 'Ivan Franko Branch', 'Anne Frank\'s diary from hiding during WWII.', 4.8),
            Book('25', 'The Rise and Fall of the Third Reich', 'William L. Shirer', 'history', 1960, 3, 3, 'East Branch', 'Comprehensive history of Nazi Germany.', 4.4),
            Book('26', 'Band of Brothers', 'Stephen E. Ambrose', 'history', 1992, 4, 4, 'Central Branch', 'Easy Company in WWII.', 4.7),
            Book('27', 'The Immortal Life of Henrietta Lacks', 'Rebecca Skloot', 'history', 2010, 3, 3, 'West Branch', 'The story of HeLa cells and medical ethics.', 4.5),
            Book('28', 'The Devil in the White City', 'Erik Larson', 'history', 2003, 4, 4, 'North Branch', 'Murder and the World\'s Fair.', 4.6),
            Book('29', 'Unbroken', 'Laura Hillenbrand', 'history', 2010, 5, 5, 'South Branch', 'Louis Zamperini\'s WWII survival story.', 4.8),
            Book('30', 'The Warmth of Other Suns', 'Isabel Wilkerson', 'history', 2010, 3, 3, 'East Branch', 'The Great Migration of African Americans.', 4.7),
            
            Book('31', 'To Kill a Mockingbird', 'Harper Lee', 'drama', 1960, 5, 5, 'Central Branch', 'Racism and injustice in the American South.', 4.9),
            Book('32', 'The Great Gatsby', 'F. Scott Fitzgerald', 'drama', 1925, 4, 4, 'West Branch', 'The American Dream in the Jazz Age.', 4.4),
            Book('33', '1984', 'George Orwell', 'drama', 1949, 6, 6, 'North Branch', 'Totalitarian dystopia and surveillance.', 4.7),
            Book('34', 'Pride and Prejudice', 'Jane Austen', 'drama', 1813, 4, 4, 'South Branch', 'Elizabeth Bennet and Mr. Darcy.', 4.6),
            Book('35', 'The Catcher in the Rye', 'J.D. Salinger', 'drama', 1951, 3, 3, 'East Branch', 'Holden Caulfield\'s teenage angst.', 4.2),
            Book('36', 'One Hundred Years of Solitude', 'Gabriel García Márquez', 'drama', 1967, 4, 4, 'Central Branch', 'The Buendía family saga.', 4.5),
            Book('37', 'The Bell Jar', 'Sylvia Plath', 'drama', 1963, 3, 3, 'West Branch', 'Esther Greenwood\'s mental health struggles.', 4.3),
            Book('38', 'The Handmaid\'s Tale', 'Margaret Atwood', 'drama', 1985, 5, 5, 'North Branch', 'Dystopian society in Gilead.', 4.6),
            Book('39', 'Norwegian Wood', 'Haruki Murakami', 'drama', 1987, 3, 3, 'South Branch', 'Love and loss in 1960s Tokyo.', 4.4),
            Book('40', 'The Kite Runner', 'Khaled Hosseini', 'drama', 2003, 4, 4, 'East Branch', 'Friendship and betrayal in Afghanistan.', 4.8),
            
            Book('41', 'A Brief History of Time', 'Stephen Hawking', 'science', 1988, 4, 4, 'Central Branch', 'From big bang to black holes.', 4.5),
            Book('42', 'The Gene: An Intimate History', 'Siddhartha Mukherjee', 'science', 2016, 3, 3, 'West Branch', 'The story of the gene.', 4.6),
            Book('43', 'Sapiens: A Brief History of Humankind', 'Yuval Noah Harari', 'science', 2011, 4, 4, 'North Branch', 'Evolution of human societies.', 4.7),
            Book('44', 'The Body Keeps the Score', 'Bessel van der Kolk', 'science', 2014, 3, 3, 'South Branch', 'Trauma and the body.', 4.8),
            Book('45', 'Thinking, Fast and Slow', 'Daniel Kahneman', 'science', 2011, 4, 4, 'East Branch', 'Psychology of thinking and decision-making.', 4.4),
            Book('46', 'The Emperor of All Maladies', 'Siddhartha Mukherjee', 'science', 2010, 3, 3, 'Central Branch', 'A biography of cancer.', 4.7),
            Book('47', 'Guns, Germs, and Steel', 'Jared Diamond', 'science', 1997, 4, 4, 'West Branch', 'Geography and human history.', 4.5),
            Book('48', 'The Sixth Extinction', 'Elizabeth Kolbert', 'science', 2014, 3, 3, 'North Branch', 'The current mass extinction event.', 4.6),
            Book('49', 'Entangled Life', 'Merlin Sheldrake', 'science', 2020, 4, 4, 'South Branch', 'The world of fungi.', 4.7),
            Book('50', 'The Code Breaker', 'Walter Isaacson', 'science', 2021, 3, 3, 'East Branch', 'Jennifer Doudna and CRISPR.', 4.5),
            
            Book('51', 'The Innovators', 'Walter Isaacson', 'tech', 2014, 4, 4, 'Central Branch', 'The digital revolution.', 4.4),
            Book('52', 'Hackers', 'Steven Levy', 'tech', 1984, 3, 3, 'West Branch', 'The history of hacking.', 4.3),
            Book('53', 'The Master Switch', 'Tim Wu', 'tech', 2010, 4, 4, 'North Branch', 'The rise of information empires.', 4.5),
            Book('54', 'Superintelligence', 'Nick Bostrom', 'tech', 2014, 3, 3, 'South Branch', 'Paths, dangers, strategies for AI.', 4.2),
            Book('55', 'The Code Book', 'Simon Singh', 'tech', 1999, 4, 4, 'East Branch', 'The science of secrecy from ancient Egypt to quantum cryptography.', 4.4),
            Book('56', 'Weapons of Math Destruction', 'Cathy O\'Neil', 'tech', 2016, 3, 3, 'Central Branch', 'How big data increases inequality.', 4.6),
            Book('57', 'Life 3.0', 'Max Tegmark', 'tech', 2017, 4, 4, 'West Branch', 'Being human in the age of AI.', 4.3),
            Book('58', 'The Alignment Problem', 'Brian Christian', 'tech', 2020, 3, 3, 'North Branch', 'Machine learning and human values.', 4.5),
            Book('59', 'The Phoenix Project', 'Gene Kim', 'tech', 2013, 4, 4, 'South Branch', 'A novel about DevOps and IT management.', 4.4),
            Book('60', 'Clean Code', 'Robert C. Martin', 'tech', 2008, 3, 3, 'East Branch', 'A handbook of agile software craftsmanship.', 4.7),
        ]
        
        for book in sample_books:
            safe_genre = book.genre.replace(' ', '_').lower()
            book.cover_path = f'assets/covers/{safe_genre}_{book.id}.jpg'
            book.file_content_path = f'assets/library/{safe_genre}_{book.id}.txt'
            self.books[book.id] = book
        self.save_data()

    def save_data(self):
        with open('data/auth_vault.txt', 'w', encoding='utf-8') as f:
            for user in self.users.values():
                f.write(
                    json_line_encode(
                        {
                            'user_id': hash(user.username) % 1000000,  # Simple ID
                            'username': user.username,
                            'password_hash': user.password_hash.hex(),
                            'salt': user.salt.hex(),
                            'role': user.role,
                            'failed_attempts': user.failed_attempts,
                            'lockout_until': user.lockout_until,
                        }
                    ) + '\n'
                )

        with open('data/profile_vault.txt', 'w', encoding='utf-8') as f:
            for user in self.users.values():
                f.write(
                    json_line_encode(
                        {
                            'username': user.username,
                            'encrypted_personal_data': user.encrypted_personal_data,
                        }
                    ) + '\n'
                )

        with open('data/books.txt', 'w', encoding='utf-8') as f:
            for book in self.books.values():
                f.write(json_line_encode(book.to_record()) + '\n')

        with open('data/reviews.txt', 'w', encoding='utf-8') as f:
            for review in self.reviews:
                f.write(json_line_encode(review.to_record()) + '\n')

        with open('data/reservations.txt', 'w', encoding='utf-8') as f:
            for reservation in self.reservations:
                f.write(json_line_encode(reservation.to_record()) + '\n')

    def compute_checksum(self, entry_text):
        return hashlib.sha256(entry_text.encode()).hexdigest()

    def log_operation(self, action, details):
        timestamp = datetime.datetime.now().isoformat()
        result = details.get('result', 'SUCCESS')
        details_safe = dict(details)
        details_safe.pop('result', None)
        entry = f"[{timestamp}] | ACTION: {action} | DETAILS: {json.dumps(details_safe, ensure_ascii=False)} | RESULT: {result}"
        checksum = self.compute_checksum(entry)
        with open('data/system.log', 'a', encoding='utf-8') as f:
            f.write(f"{entry} | CHECKSUM: {checksum}\n")

    def filter_books(self, criteria):
        self.cleanup_expired_reservations()
        books = list(self.books.values())
        search_text = sanitize_input(criteria.get('title', '')).strip().lower()
        author = sanitize_input(criteria.get('author', '')).strip().lower()
        genre = sanitize_input(criteria.get('genre', '')).strip().lower()
        status = sanitize_input(criteria.get('status', 'all')).strip().lower()

        if search_text and search_text not in {'search by title or isbn...', 'search by title or isbn'}:
            books = [
                book for book in books
                if search_text in book.title.lower()
                or search_text in book.author.lower()
                or search_text in book.genre.lower()
                or search_text in book.description.lower()
                or search_text in book.id.lower()
            ]
        if author and author not in {'all authors', 'all'}:
            books = [book for book in books if author in book.author.lower()]
        if genre and genre not in {'all genres', 'all'}:
            books = [book for book in books if genre in book.genre.lower()]
        if status == 'available':
            books = [book for book in books if book.available]
        elif status == 'unavailable':
            books = [book for book in books if not book.available]

        return books

    def get_book_reviews(self, book_id):
        return [review for review in self.reviews if review.book_id == book_id]

    def get_book_rating(self, book_id):
        reviews = self.get_book_reviews(book_id)
        if not reviews:
            return 0.0
        return sum(review.rating for review in reviews) / len(reviews)

    def cleanup_expired_reservations(self):
        expired = [reservation for reservation in self.reservations if not reservation.is_active()]
        for reservation in expired:
            book = self.books.get(reservation.book_id)
            if book:
                book.available_copies = min(book.total_copies, book.available_copies + 1)
            self.reservations.remove(reservation)
        if expired:
            self.save_data()

    def reserve_book(self, user_id, book_id):
        return self.reservation_system.reserve_book(user_id, book_id)

    def get_active_reservations(self, username):
        return self.reservation_system.get_active_reservations(username)

    def open_book(self, username, book_id):
        return self.reservation_system.open_book(username, book_id)

    def update_password(self, username, current_password, new_password):
        user = self.users.get(username)
        if not user:
            raise ValueError('User not found')
        if not user.authenticate(current_password):
            raise ValueError('Current password is incorrect')
        hashed, salt = hash_password(new_password)
        user.password_hash = hashed
        user.salt = salt
        self.save_data()
        self.log_operation('password_changed', {'username': username})

    def add_review(self, username, book_id, rating, comment):
        if username not in self.users:
            raise ValueError('User not found')
        if book_id not in self.books:
            raise ValueError('Book not found')
        if not 1 <= int(rating) <= 5:
            raise ValueError('Rating must be between 1 and 5')
        if not comment or not comment.strip():
            raise ValueError('Comment cannot be empty')

        safe_comment = sanitize_input(comment.strip())
        review = Review(username, book_id, int(rating), safe_comment)
        self.reviews.append(review)
        self.save_data()
        self.log_operation('review_added', review.to_record())
        return review

    def delete_user_data(self, user_id):
        if user_id in self.users:
            del self.users[user_id]
        self.reviews = [review for review in self.reviews if review.username != user_id]
        self.reservations = [reservation for reservation in self.reservations if reservation.username != user_id]
        self.save_data()
        self.log_operation('delete_user_data', {'username': user_id})

    def reset_password_by_email(self, username, email, new_password):
        user = self.users.get(username)
        if not user:
            raise ValueError('User not found')
        profile_data = user.get_personal_data(self.aes_key)
        if profile_data.get('email') != email:
            raise ValueError('Email does not match')
        hashed, salt = hash_password(new_password)
        user.password_hash = hashed
        user.salt = salt
        user.reset_lockout()
        self.save_data()
        self.log_operation('password_reset', {'username': username, 'result': 'SUCCESS'})

    def add_book(self, book):
        self.books[book.id] = book
        self.save_data()
        self.log_operation('book_added', book.to_record())

    def recover_from_log(self):
        self.users = {}
        self.books = {}
        self.reviews = []
        self.reservations = []
        if not os.path.exists('data/system.log'):
            return

        with open('data/system.log', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if ' | CHECKSUM: ' not in line:
                    continue
                raw_entry, checksum = line.rsplit(' | CHECKSUM: ', 1)
                if self.compute_checksum(raw_entry) != checksum:
                    continue
                parts = raw_entry.split(' | ')
                if len(parts) < 4:
                    continue
                action = parts[1].split(': ', 1)[1]
                details_raw = parts[2].split(': ', 1)[1]
                result = parts[3].split(': ', 1)[1] if ': ' in parts[3] else ''
                if result != 'SUCCESS':
                    continue
                try:
                    details = json.loads(details_raw)
                except json.JSONDecodeError:
                    continue

                if action in {'user_registered', 'user_added', 'google_login'}:
                    username = details.get('username')
                    if username and username not in self.users:
                        personal_data = {
                            'email': username,
                            'name': details.get('name', username),
                            'phone': '',
                            'address': '',
                            'favorites': [],
                            'profile_picture_path': 'No image selected',
                        }
                        user = User.create_user(username, 'recovery_temp', details.get('role', 'client'), personal_data)
                        user.set_encryption_key(self.aes_key)
                        self.users[username] = user
                elif action == 'book_added':
                    try:
                        book_record = details
                        book = Book.from_record(book_record)
                        self.books[book.id] = book
                    except Exception:
                        continue
                elif action == 'review_added':
                    try:
                        review = Review.from_record(details)
                        if review.book_id in self.books and review.username in self.users:
                            self.reviews.append(review)
                    except Exception:
                        continue
                elif action == 'reservation_created':
                    try:
                        reservation = Reservation.from_record(details)
                        book = self.books.get(reservation.book_id)
                        if reservation.username in self.users and book:
                            self.reservations.append(reservation)
                            book.available_copies = max(0, book.available_copies - 1)
                    except Exception:
                        continue
                elif action == 'delete_user_data':
                    username = details.get('username')
                    if username and username in self.users:
                        del self.users[username]
                        self.reviews = [r for r in self.reviews if r.username != username]
                        self.reservations = [r for r in self.reservations if r.username != username]

        self.cleanup_expired_reservations()
        self.save_data()

    def login(self, username, password):
        user = self.users.get(username)
        if not user:
            self.log_operation('login', {'username': username, 'result': 'FAILURE'})
            return None
        if user.is_locked():
            self.log_operation('login_locked', {'username': username, 'result': 'LOCKED'})
            raise ValueError('Too many failed attempts. Please wait before trying again.')
        if user.authenticate(password):
            user.reset_lockout()
            self.save_data()
            self.log_operation('login', {'username': username, 'result': 'SUCCESS'})
            return user
        user.record_failed_attempt()
        self.save_data()
        self.log_operation('login', {'username': username, 'result': 'FAILURE', 'attempts': user.failed_attempts})
        raise ValueError('Invalid credentials')

    def google_login(self, email):
        """Simulate Google login by finding the account and creating/updating user."""
        account = next((acc for acc in self.google_accounts if acc['email'] == email), None)
        if not account:
            return None

        username = email
        if username not in self.users:
            personal_data = {
                'email': email,
                'name': account['name'],
                'phone': '',
                'address': '',
                'favorites': [],
                'profile_picture_path': 'No image selected',
            }
            user = User.create_user(username, 'google_auth', 'client', personal_data)
            user.register(self)
            user.set_encryption_key(self.aes_key)
        user = self.users[username]
        self.log_operation('google_login', {'username': username, 'result': 'SUCCESS'})
        return user

    def recovery_tool(self):
        """Execute a full recovery of the database from the audit log."""
        self.recover_from_log()


class ReservationSystem:
    def __init__(self, library_system: LibrarySystem):
        self.library = library_system

    def generate_unique_reservation_id(self):
        import random
        import string
        while True:
            token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            token = f"{token[:2]}-{token[2:6]}-{token[6:]}"
            if not any(r.reservation_id == token for r in self.library.reservations):
                return token

    def reserve_book(self, user_id, book_id):
        user = self.library.users.get(user_id)
        if not user:
            raise ValueError('User not found')
        book = self.library.books.get(book_id)
        if not book:
            raise ValueError('Book not found')

        self.library.cleanup_expired_reservations()
        if book.available_copies < 1:
            raise ValueError('Book is not available for reservation')

        reservation_id = self.generate_unique_reservation_id()
        start_time = datetime.datetime.now().isoformat()
        expiry_time = (datetime.datetime.now() + datetime.timedelta(hours=1)).isoformat()
        reservation = Reservation(user_id, book_id, book.title, start_time, expiry_time, reservation_id)
        self.library.reservations.append(reservation)
        book.available_copies -= 1
        self.library.save_data()
        self.library.log_operation('reservation_created', reservation.to_record())
        return reservation

    def get_active_reservations(self, username):
        self.library.cleanup_expired_reservations()
        return [reservation for reservation in self.library.reservations if reservation.username == username and reservation.is_active()]

    def open_book(self, username, book_id):
        user = self.library.users.get(username)
        book = self.library.books.get(book_id)
        if not user:
            raise ValueError('User not found')
        if not book:
            raise ValueError('Book not found')

        authorized = user.role in {'admin', 'advanced'} or any(
            reservation.username == username and reservation.book_id == book_id and reservation.is_active()
            for reservation in self.library.reservations
        )

        if not authorized:
            raise PermissionError('Access denied for this book preview')

        if not os.path.exists(book.file_content_path):
            raise FileNotFoundError('Book preview file not found')

        lines = []
        with open(book.file_content_path, 'r', encoding='utf-8') as f:
            for _ in range(10):
                line = f.readline()
                if not line:
                    break
                lines.append(line)
        preview_text = ''.join(lines)
        print(preview_text)
        return preview_text


class AuthManager:
    def __init__(self, library_system: LibrarySystem):
        self.library = library_system

    def authenticate(self, username, password):
        return self.library.login(username, password)

    def google_authenticate(self, email):
        return self.library.google_login(email)

    def register_user(self, username, password, role, personal_data):
        user = User.create_user(username, password, role, personal_data)
        user.register(self.library)
        return user


class SecurityAudit:
    def __init__(self, library_system: LibrarySystem):
        self.library = library_system

    def verify_log_integrity(self, log_path='data/system.log'):
        if not os.path.exists(log_path):
            return False
        with open(log_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if ' | CHECKSUM: ' not in line:
                    return False
                raw_entry, checksum = line.rsplit(' | CHECKSUM: ', 1)
                if self.library.compute_checksum(raw_entry) != checksum:
                    return False
        return True

    def rebuild_state(self):
        self.library.recovery_tool()
