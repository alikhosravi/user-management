# GIBD Services - API Key Management System

A Flask-based user authentication and API key management system with email verification, admin dashboard, and usage tracking.

## Features

- User registration with email verification
- Secure login system with password hashing
- API key generation (format: gibd-services-XXXXXXXXXXXX)
- Admin dashboard to manage users
- Credit system ($50 default per user)
- Token usage tracking per LLM model
- RESTful API endpoints for external integration
- SQLite database for data persistence

## Installation

1. Install dependencies:
\`\`\`bash
pip install -r requirements.txt
\`\`\`

2. Configure email settings in `app.py`:
   - Update `SENDER_EMAIL` and `SENDER_PASSWORD` with your Gmail credentials
   - Use an App Password for Gmail (not your regular password)

3. Run the application:
\`\`\`bash
python app.py
\`\`\`

4. Access the application at `http://localhost:5000`

## Default Admin Account

- Username: `admin`
- Password: `admin123`
- **Important:** Change this password after first login!

## Database Schema

### Users Table
- id, username, email, password (hashed)
- first_name, last_name, country, phone_number
- is_admin, is_verified, verification_token
- remaining_credit (default: $50.00)
- created_at

### API Keys Table
- id, user_id, api_key, created_at

### Usage Table
- id, user_id, llm_model, used_tokens, cost, created_at

## API Endpoints

### 1. Check Credit Status
**Endpoint:** `POST /api/check-credit`

**Request:**
\`\`\`json
{
  "api_key": "gibd-services-xxxxxxxxxxxx"
}
\`\`\`

**Response:**
\`\`\`json
{
  "user_authorized": "Yes",
  "credit": "Yes",
  "remaining_credit": 45.50
}
\`\`\`

### 2. Update Token Usage
**Endpoint:** `POST /api/update-usage`

**Request:**
\`\`\`json
{
  "api_key": "gibd-services-xxxxxxxxxxxx",
  "tokens": 150,
  "llm_model": "OpenAI-GPT-4o",
  "cost": 0.025
}
\`\`\`

**Response:**
\`\`\`json
{
  "success": true,
  "message": "Usage updated successfully",
  "remaining_credit": 49.98,
  "cumulative_tokens": 150,
  "llm_model": "OpenAI-GPT-4o"
}
\`\`\`

**Note:** Token usage is cumulative per model. If a user has used 10 tokens for "OpenAI-GPT-4o" and then uses 15 more, the cumulative total will be 25 tokens.

## Testing the API

Use the included `test_api.py` script to test the API endpoints:

\`\`\`bash
python test_api.py
\`\`\`

Make sure to update the `API_KEY` variable in the script with a valid key from your database.

## Security Notes

- Passwords are hashed using SHA-256
- Email verification required before API key generation
- Session-based authentication
- Admin-only routes protected with decorators
- API endpoints validate API keys before processing requests
