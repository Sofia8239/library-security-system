# library-security-system
An OOP-based Python application featuring a custom flat-file database, Role-Based Access Control (RBAC), and advanced data protection. Implements password hashing, AES encryption for personal data, and a transaction-based logging system for database recovery.

## New Features (2026 Update)
- **Like System**: Persistent favorite books with Gold Heart toggle
- **Unique Reservation Engine**: 8-char codes (SL-XXXX-XXXX) with 60-min TTL
- **Google Auth Simulation**: Modal with 3 mock accounts
- **Mobile-First UI**: iPhone-simulated container (430px max-width)
- **Cross-Platform Responsive**: Adapts to desktop (1200px), tablet (600px), mobile (430px)
- **Bottom Navigation Dock**: Fixed nav with Home/Favorites/Profile
- **My Reservations**: Tickets with countdown timers
- **Avatar Upload**: File upload to encrypted profiles
- **GDPR Wipe**: Complete data deletion with confirmation
- **Audit Logging**: SHA-256 integrity for all operations

To run the browser interface:

    python frontend/gui.py

Then open http://127.0.0.1:5002 in your browser.

## Responsive Design
- **Mobile (< 480px)**: Single column, touch-optimized, 430px max-width
- **Tablet (480px - 767px)**: 2-column grid, 600px max-width
- **Desktop (> 768px)**: Multi-column grid, full-width layout, horizontal nav items
