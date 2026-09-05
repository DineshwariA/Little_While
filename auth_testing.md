# Little While authentication testing

The app uses email/password auth with bcrypt and short-lived JWT access cookies plus refresh cookies.

## API checks

1. Register with `POST /api/auth/register` using email, password (8+ characters), and display_name.
2. Confirm the response sets `access_token` and `refresh_token` cookies.
3. Call `GET /api/auth/me` with those cookies and confirm the same user is returned.
4. Call `GET /api/activities` and confirm starter activities belong to the registered user.
5. Register a second user and confirm the first user's activities do not appear.
6. Login, logout, then confirm `/api/auth/me` returns 401.
7. Forgot password returns a generic success message and logs a one-hour reset link server-side.
8. Five failed attempts for the same normalized email return 401 for attempts one through five, then 429 for 15 minutes.

Google sign-in is intentionally credential-gated. The button gives a friendly setup response until GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are configured.