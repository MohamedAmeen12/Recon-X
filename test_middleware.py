"""
Test script to verify authentication middleware is working
"""
import sys
import os

# Add project root to path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from app import app

def test_protected_routes():
    """Test that protected routes redirect to login"""
    with app.test_client() as client:
        # Test routes that should redirect to login
        protected_routes = [
            '/home',
            '/scan',
            '/report',
            '/history',
            '/admin',
            '/admin/pending-users',
            '/admin/user-logs',
            '/admin/user-edit'
        ]
        
        print("=" * 60)
        print("Testing Protected Routes (Should Redirect to /login)")
        print("=" * 60)
        
        for route in protected_routes:
            response = client.get(route, follow_redirects=False)
            
            if response.status_code == 302:  # Redirect
                location = response.headers.get('Location', '')
                if '/login' in location:
                    print(f"[OK] {route:30} -> Redirects to login")
                else:
                    print(f"[FAIL] {route:30} -> Redirects to {location} (WRONG!)")
            else:
                print(f"[FAIL] {route:30} -> Status {response.status_code} (NOT REDIRECTING!)")
        
        print("\n" + "=" * 60)
        print("Testing Public Routes (Should Be Accessible)")
        print("=" * 60)
        
        public_routes = ['/', '/login', '/signup']
        for route in public_routes:
            response = client.get(route)
            if response.status_code == 200:
                print(f"[OK] {route:30} -> Accessible (200 OK)")
            else:
                print(f"[FAIL] {route:30} -> Status {response.status_code}")

if __name__ == "__main__":
    test_protected_routes()
