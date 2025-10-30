"""
Test script for the API endpoints
This demonstrates how to use the /api/update-usage and /api/check-credit endpoints
"""

import requests
import json

# Base URL of your Flask server
BASE_URL = "http://localhost:5000"

# Replace with a valid API key from your database
API_KEY = "gibd-services-XXXXXXXXXXXX"

def test_check_credit():
    """Test the credit checking endpoint"""
    print("\n=== Testing Credit Check ===")
    
    url = f"{BASE_URL}/api/check-credit"
    payload = {
        "api_key": API_KEY
    }
    
    response = requests.post(url, json=payload)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    return response.json()

def test_update_usage():
    """Test the usage update endpoint"""
    print("\n=== Testing Usage Update ===")
    
    url = f"{BASE_URL}/api/update-usage"
    payload = {
        "api_key": API_KEY,
        "tokens": 150,
        "llm_model": "OpenAI-GPT-4o",
        "cost": 0.025
    }
    
    response = requests.post(url, json=payload)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    return response.json()

def test_cumulative_usage():
    """Test cumulative token tracking"""
    print("\n=== Testing Cumulative Usage ===")
    
    url = f"{BASE_URL}/api/update-usage"
    
    # First request
    print("\nFirst request (10 tokens):")
    payload1 = {
        "api_key": API_KEY,
        "tokens": 10,
        "llm_model": "OpenAI-GPT-4o-mini",
        "cost": 0.005
    }
    response1 = requests.post(url, json=payload1)
    print(f"Response: {json.dumps(response1.json(), indent=2)}")
    
    # Second request (same model)
    print("\nSecond request (15 tokens, same model):")
    payload2 = {
        "api_key": API_KEY,
        "tokens": 15,
        "llm_model": "OpenAI-GPT-4o-mini",
        "cost": 0.0075
    }
    response2 = requests.post(url, json=payload2)
    print(f"Response: {json.dumps(response2.json(), indent=2)}")
    print(f"Cumulative tokens should be 25: {response2.json().get('cumulative_tokens')}")

def test_invalid_api_key():
    """Test with invalid API key"""
    print("\n=== Testing Invalid API Key ===")
    
    url = f"{BASE_URL}/api/check-credit"
    payload = {
        "api_key": "invalid-key-12345"
    }
    
    response = requests.post(url, json=payload)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

if __name__ == "__main__":
    print("API Testing Script")
    print("=" * 50)
    print(f"Make sure your Flask server is running at {BASE_URL}")
    print(f"Update the API_KEY variable with a valid key from your database")
    print("=" * 50)
    
    try:
        # Test credit check
        test_check_credit()
        
        # Test usage update
        test_update_usage()
        
        # Test cumulative usage
        test_cumulative_usage()
        
        # Test invalid key
        test_invalid_api_key()
        
        # Final credit check
        print("\n=== Final Credit Check ===")
        test_check_credit()
        
    except requests.exceptions.ConnectionError:
        print("\nError: Could not connect to the server.")
        print("Make sure the Flask server is running at", BASE_URL)
    except Exception as e:
        print(f"\nError: {str(e)}")
