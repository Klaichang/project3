import pytest
import sqlite3
from main import app, init_db

@pytest.fixture
def client():
    """Fixture to set up and tear down a test client."""
    app.config['TESTING'] = True
    init_db()  # Reinitialize the database for tests
    with app.test_client() as client:
        yield client

def test_register_user(client):
    """Test the /register endpoint."""
    response = client.post('/register', json={
        'username': 'testuser',
        'email': 'testuser@example.com'
    })
    assert response.status_code == 201
    assert 'password' in response.get_json()

def test_register_existing_user(client):
    """Test registering a user that already exists."""
    client.post('/register', json={
        'username': 'existinguser',
        'email': 'existinguser@example.com'
    })
    response = client.post('/register', json={
        'username': 'existinguser',
        'email': 'existinguser@example.com'
    })
    assert response.status_code == 409
    assert response.get_json() == {'error': 'Username or email already exists.'}

def test_authenticate_user(client):
    """Test the /auth endpoint."""
    # Register a user first
    register_response = client.post('/register', json={
        'username': 'authuser',
        'email': 'authuser@example.com'
    })
    password = register_response.get_json()['password']

    # Authenticate the user
    response = client.post('/auth', json={
        'username': 'authuser',
        'password': password
    })
    assert response.status_code == 200
    assert 'token' in response.get_json()

def test_auth_invalid_user(client):
    """Test authentication with invalid username."""
    response = client.post('/auth', json={
        'username': 'nonexistent',
        'password': 'password123'
    })
    assert response.status_code == 401
    assert response.get_json() == {'error': 'Invalid username.'}

def test_auth_invalid_password(client):
    """Test authentication with an invalid password."""
    # Register a user first
    client.post('/register', json={
        'username': 'invalidpass',
        'email': 'invalidpass@example.com'
    })

    # Attempt to authenticate with wrong password
    response = client.post('/auth', json={
        'username': 'invalidpass',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
    assert response.get_json() == {'error': 'Invalid password.'}

def test_rate_limiting(client):
    """Test rate limiting on /auth endpoint."""
    # Register a user first
    register_response = client.post('/register', json={
        'username': 'ratelimituser',
        'email': 'ratelimit@example.com'
    })
    password = register_response.get_json()['password']

    # Hit the /auth endpoint more than the limit
    for _ in range(15):  # Assuming limit is 10/sec
        client.post('/auth', json={
            'username': 'ratelimituser',
            'password': password
        })

    response = client.post('/auth', json={
        'username': 'ratelimituser',
        'password': password
    })
    assert response.status_code == 429
    assert response.get_json() == {'error': 'Too many requests. Please try again later.'}
