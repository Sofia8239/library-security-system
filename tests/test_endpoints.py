import importlib
import os
import sys
import tempfile
import shutil
import unittest

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

class TestEndpoints(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.old_cwd = os.getcwd()
        os.chdir(self.tempdir.name)
        shutil.copytree(os.path.join(os.path.dirname(__file__), '..', 'assets'), os.path.join(self.tempdir.name, 'assets'))

        os.environ['LIBRARY_BASE_PATH'] = self.tempdir.name
        import frontend.gui as gui
        importlib.reload(gui)

        self.gui = gui
        self.app = gui.app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.library = gui.library

        assets_book_dir = os.path.join(self.tempdir.name, 'assets', 'library')
        os.makedirs(assets_book_dir, exist_ok=True)
        with open(os.path.join(assets_book_dir, 'test_book.txt'), 'w', encoding='utf-8') as f:
            f.write('First line\nSecond line\nThird line\n')

        from backend.library_system import Book
        test_book = Book(
            'test1',
            'Test Book',
            'Author Example',
            'test',
            2024,
            total_copies=1,
            available_copies=1,
            location='Test Branch',
            description='A test book for endpoint checks.',
            rating=4.2,
            cover_front_path='assets/covers/test1_front.jpg',
            file_content_path='assets/library/test_book.txt',
        )
        self.library.add_book(test_book)

    def tearDown(self):
        os.chdir(self.old_cwd)
        self.tempdir.cleanup()
        os.environ.pop('LIBRARY_BASE_PATH', None)

    def test_login_page_loads(self):
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Увійдіть у свій обліковий запис', response.get_data(as_text=True))

    def test_register_and_access_home(self):
        response = self.client.post(
            '/register',
            data={
                'full_name': 'Test User',
                'email': 'testuser@example.com',
                'password': 'Password123!',
                'phone': '+380501234567',
                'city': 'Lviv',
                'birth_date': '1990-01-01',
                'address': 'Shevchenka 1',
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('аватар', response.get_data(as_text=True))

        response = self.client.get('/home')
        self.assertEqual(response.status_code, 200)
        self.assertIn('SafeLibrary', response.get_data(as_text=True))

    def login_test_user(self):
        self.client.post(
            '/register',
            data={
                'full_name': 'Test User',
                'email': 'testuser@example.com',
                'password': 'Password123!',
            },
            follow_redirects=True,
        )

    def test_home_requires_login(self):
        response = self.client.get('/home', follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers.get('Location', ''))

    def test_book_detail_and_reserve(self):
        self.login_test_user()

        response = self.client.get('/book/test1')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test Book', response.get_data(as_text=True))

        response = self.client.get('/reserve/test1', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Книга заброньована', response.get_data(as_text=True))

    def test_favorite_toggle_endpoint(self):
        self.login_test_user()

        response = self.client.post('/favorite/test1')
        self.assertEqual(response.status_code, 200)
        self.assertIn('success', response.get_data(as_text=True))

        response = self.client.post('/favorite/test1')
        self.assertEqual(response.status_code, 200)
        self.assertIn('success', response.get_data(as_text=True))

    def test_logout_redirects(self):
        self.login_test_user()
        response = self.client.get('/logout', follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers.get('Location', ''))

if __name__ == '__main__':
    unittest.main()
