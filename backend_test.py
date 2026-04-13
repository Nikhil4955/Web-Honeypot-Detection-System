import requests
import sys
import json
from datetime import datetime

class SOINAPITester:
    def __init__(self, base_url="https://ai-dev-workspace-7.preview.emergentagent.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.tests_run = 0
        self.tests_passed = 0
        self.user_id = None
        self.project_id = None

    def run_test(self, name, method, endpoint, expected_status, data=None, cookies=None):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = self.session.get(url, headers=headers)
            elif method == 'POST':
                response = self.session.post(url, json=data, headers=headers)
            elif method == 'PUT':
                response = self.session.put(url, json=data, headers=headers)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    response_data = response.json()
                    print(f"   Response: {json.dumps(response_data, indent=2)[:200]}...")
                    return True, response_data
                except:
                    return True, {}
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"   Error: {error_data}")
                except:
                    print(f"   Error: {response.text}")
                return False, {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_health_check(self):
        """Test health endpoint"""
        return self.run_test("Health Check", "GET", "api/health", 200)

    def test_register(self, email, password, name):
        """Test user registration"""
        success, response = self.run_test(
            "User Registration",
            "POST",
            "api/auth/register",
            200,
            data={"email": email, "password": password, "name": name}
        )
        if success and '_id' in response:
            self.user_id = response['_id']
        return success, response

    def test_login(self, email, password):
        """Test user login"""
        success, response = self.run_test(
            "User Login",
            "POST",
            "api/auth/login",
            200,
            data={"email": email, "password": password}
        )
        if success and '_id' in response:
            self.user_id = response['_id']
        return success, response

    def test_get_me(self):
        """Test get current user"""
        return self.run_test("Get Current User", "GET", "api/auth/me", 200)

    def test_refresh_token(self):
        """Test token refresh"""
        return self.run_test("Refresh Token", "POST", "api/auth/refresh", 200)

    def test_create_project(self, name):
        """Test project creation"""
        success, response = self.run_test(
            "Create Project",
            "POST",
            "api/projects",
            200,
            data={"name": name}
        )
        if success and '_id' in response:
            self.project_id = response['_id']
        return success, response

    def test_get_projects(self):
        """Test get user projects"""
        return self.run_test("Get Projects", "GET", "api/projects", 200)

    def test_get_project(self, project_id):
        """Test get specific project"""
        return self.run_test("Get Project", "GET", f"api/projects/{project_id}", 200)

    def test_add_collaborator(self, project_id, email):
        """Test adding collaborator"""
        return self.run_test(
            "Add Collaborator",
            "POST",
            f"api/projects/{project_id}/collaborators",
            200,
            data={"email": email}
        )

    def test_get_collaborators(self, project_id):
        """Test get project collaborators"""
        return self.run_test("Get Collaborators", "GET", f"api/projects/{project_id}/collaborators", 200)

    def test_update_file_tree(self, project_id, file_tree):
        """Test file tree update"""
        return self.run_test(
            "Update File Tree",
            "PUT",
            f"api/projects/{project_id}/filetree",
            200,
            data={"fileTree": file_tree}
        )

    def test_logout(self):
        """Test user logout"""
        return self.run_test("User Logout", "POST", "api/auth/logout", 200)

def main():
    print("🚀 Starting SOIN API Tests...")
    tester = SOINAPITester()
    
    # Test credentials from test_credentials.md
    admin_email = "admin@soin.dev"
    admin_password = "admin123"
    
    test_user_email = f"test_user_{datetime.now().strftime('%H%M%S')}@test.com"
    test_user_password = "TestPass123!"
    test_user_name = "Test User"
    
    # Test 1: Health Check
    print("\n" + "="*50)
    print("TESTING BASIC CONNECTIVITY")
    print("="*50)
    
    success, _ = tester.test_health_check()
    if not success:
        print("❌ Health check failed - API not accessible")
        return 1

    # Test 2: Authentication Flow
    print("\n" + "="*50)
    print("TESTING AUTHENTICATION")
    print("="*50)
    
    # Test admin login
    success, _ = tester.test_login(admin_email, admin_password)
    if not success:
        print("❌ Admin login failed")
        return 1
    
    # Test get current user
    success, _ = tester.test_get_me()
    if not success:
        print("❌ Get current user failed")
    
    # Test token refresh
    success, _ = tester.test_refresh_token()
    if not success:
        print("❌ Token refresh failed")
    
    # Test logout
    success, _ = tester.test_logout()
    if not success:
        print("❌ Logout failed")
    
    # Test new user registration
    success, _ = tester.test_register(test_user_email, test_user_password, test_user_name)
    if not success:
        print("❌ User registration failed")
        return 1
    
    # Login with new user
    success, _ = tester.test_login(test_user_email, test_user_password)
    if not success:
        print("❌ New user login failed")
        return 1

    # Test 3: Project Management
    print("\n" + "="*50)
    print("TESTING PROJECT MANAGEMENT")
    print("="*50)
    
    # Create project
    project_name = f"Test Project {datetime.now().strftime('%H%M%S')}"
    success, _ = tester.test_create_project(project_name)
    if not success:
        print("❌ Project creation failed")
        return 1
    
    # Get projects
    success, _ = tester.test_get_projects()
    if not success:
        print("❌ Get projects failed")
    
    # Get specific project
    if tester.project_id:
        success, _ = tester.test_get_project(tester.project_id)
        if not success:
            print("❌ Get specific project failed")
    
    # Test 4: Collaboration Features
    print("\n" + "="*50)
    print("TESTING COLLABORATION")
    print("="*50)
    
    if tester.project_id:
        # Add collaborator (admin)
        success, _ = tester.test_add_collaborator(tester.project_id, admin_email)
        if not success:
            print("❌ Add collaborator failed")
        
        # Get collaborators
        success, _ = tester.test_get_collaborators(tester.project_id)
        if not success:
            print("❌ Get collaborators failed")
        
        # Update file tree
        test_file_tree = {
            "app.js": "console.log('Hello SOIN!');",
            "package.json": '{"name": "test-project", "version": "1.0.0"}'
        }
        success, _ = tester.test_update_file_tree(tester.project_id, test_file_tree)
        if not success:
            print("❌ Update file tree failed")

    # Print final results
    print("\n" + "="*50)
    print("TEST RESULTS")
    print("="*50)
    print(f"📊 Tests passed: {tester.tests_passed}/{tester.tests_run}")
    
    if tester.tests_passed == tester.tests_run:
        print("🎉 All tests passed!")
        return 0
    else:
        print(f"⚠️  {tester.tests_run - tester.tests_passed} tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())