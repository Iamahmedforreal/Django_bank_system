"""
Quick test script to verify API authentication and authorization
Run this after creating a user through the API
"""

import requests
import json

BASE_URL = "http://127.0.0.1:8000/api"

def test_registration():
    """Test user registration"""
    url = f"{BASE_URL}/auth/register/"
    data = {
        "username": "testuser456",
        "email": "test456@example.com",
        "password": "securepass123",
        "password_confirm": "securepass123",
        "first_name": "Test",
        "last_name": "User"
    }
    
    response = requests.post(url, json=data)
    print("=== REGISTRATION TEST ===")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 201:
        return response.json()['access']
    return None

def test_protected_endpoint(token):
    """Test accessing protected endpoint with token"""
    url = f"{BASE_URL}/customers/"
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.get(url, headers=headers)
    print("\n=== PROTECTED ENDPOINT TEST (with token) ===")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")

def test_unauthorized_access():
    """Test accessing protected endpoint without token"""
    url = f"{BASE_URL}/customers/"
    
    response = requests.get(url)
    print("\n=== UNAUTHORIZED ACCESS TEST (no token) ===")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")

def test_account_creation(token):
    """Test creating an account"""
    url = f"{BASE_URL}/accounts/"
    headers = {"Authorization": f"Bearer {token}"}
    data = {"account_type": "checking"}
    
    response = requests.post(url, json=data, headers=headers)
    print("\n=== ACCOUNT CREATION TEST ===")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")

if __name__ == "__main__":
    # Test registration and get token
    token = test_registration()
    
    if token:
        # Test with valid token
        test_protected_endpoint(token)
        
        # Test account creation
        test_account_creation(token)
    
    # Test without token (should fail)
    test_unauthorized_access()
