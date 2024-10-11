# BullMQ Admin Dashboard

This project provides a secure admin dashboard for BullMQ using Hono.js and Redis.

## Setup Instructions

1. Clone the repository:
   ```
   git clone <repository-url>
   cd <project-directory>
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Create a `.env` file in the project root and add the following variables:
   ```
   PRIVATE_REDIS_URL=your_redis_url
   PRIVATE_QUEUE_NAMES=queue1,queue2
   PRIVATE_ADMIN_USERNAME=your_admin_username
   PRIVATE_ADMIN_PASSWORD_HASH=your_admin_password_hash
   NODE_ENV=development
   PORT=3000
   ```

4. Generate a password hash:
   ```
   npm run generate-hash
   ```
   Enter your desired admin password when prompted. Copy the generated hash to your `.env` file.

5. Start the server:
   ```
   npm start
   ```

6. Access the admin dashboard at `http://localhost:3000/admin`

## Security Features

- Password hashing using bcrypt
- Session-based authentication
- Rate limiting for login attempts
- Secure cookie settings

## Development

To run the server in development mode with hot reloading:

```
npm run dev
```

## Production

For production deployment, set `NODE_ENV=production` in your `.env` file and ensure you're using HTTPS.

```
npm run build
npm start
```

Remember to never commit your `.env` file to version control.
