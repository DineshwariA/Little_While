
## Iteration 3 (Feb 2026)
- Added Calendar View: new top-level nav `/calendar`, monthly grid of days with completed/partial/skipped sessions, day-detail panel with categories, focused minutes, outcomes, notes and next-time reflections.
- New backend endpoint `GET /api/sessions/calendar?year=&month=` — user-scoped, timezone-aware, returns per-day aggregation and month totals.
- Fixed frontend dependency conflict for Vercel: `date-fns` `4.1.0` → `^3.6.0`, `react-day-picker` `8.10.1` → `^9.0.0` (React 19 compatible). `npm install` now succeeds without `--force` / `--legacy-peer-deps`.
- Iteration 3 tests: 6/6 pytest pass, calendar UI E2E pass.

# Little While — Product Record

## Original problem statement
Build a full-stack personal intentional-time and activity tracking platform where people choose an activity, choose a realistic duration, focus, reflect, and remember their progress. The product should feel warm, calm, human, earthy brown and green, persistent, private, responsive, and unlike a generic productivity dashboard.

## Architecture decisions
- React 19 with React Router, Axios, Lucide icons, and CSS variables for a responsive earthy interface.
- FastAPI with Motor and MongoDB for server-side validation, persistent records, and user ownership checks.
- Email/password authentication uses bcrypt and JWT httpOnly cookies. Google OAuth has a credential-gated endpoint and UI placeholder until client credentials are supplied.
- Sessions are timestamp-driven and persisted in MongoDB; pause time is stored and subtracted server-side.
- Streaks and insights are derived from completed or partially completed stored sessions in the user's timezone.

## User personas
- A curious person who wants to use spare time intentionally without productivity pressure.
- A learner or builder who wants a gentle record of focused practice.

## Core requirements
- Private user accounts, starter activities copied per account, activity creation, favorites, focus timer, pause/resume, finish/reflection, history, streaks, intentions, insights, theme preference, and responsive navigation.

## Implemented (2026-09-05)
- Built Little While authentication shell, protected workspace, starter content seeding, activities/explore, home quick start, accurate persistent focus timer, pause/resume, completion reflection, journey history/search/filter, streak calculation, daily intention, insights chart, favorites, profile theme toggle, and API error states.
- Added secure reset token endpoints with server-side logging until email delivery is connected.
- Corrected streak and daily intention comparisons to use the profile timezone, and added five-attempt email lockout with a 15-minute cooldown.

## Prioritized backlog
- P0: Connect Google OAuth callback flow and email delivery for password reset.
- P1: Add calendar day detail view, Brain Gym-specific summary, and notification preferences.
- P2: Add activity editing, session restart semantics, and richer monthly trend visualizations.

## Next tasks
- Configure Google OAuth credentials and complete callback handling.
- Add email provider for password reset links.
- Expand calendar and profile preferences after the core focus flow is validated.