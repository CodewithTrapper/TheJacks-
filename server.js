require('dotenv').config();

const SESSION_SECRET = process.env.SESSION_SECRET;



const express = require("express");
const path = require("path");
const db = require("./db");
const bcrypt = require("bcrypt");
const SALT_ROUNDS = 10;
const axios = require("axios");
const session = require("express-session");
const jwt = require("jsonwebtoken");
const dns = require("dns");
dns.setDefaultResultOrder("ipv4first");
const cors = require('cors');


// ADD THESE LINES FOR VERCEL SESSIONS
const RedisStore = require("connect-redis")(session);
const { createClient } = require("redis");

// Initialize Redis client for production
let redisClient;
if (process.env.NODE_ENV === 'production') {
    redisClient = createClient({
        url: process.env.REDIS_URL || process.env.UPSTASH_REDIS_URL
    });
    redisClient.connect().catch(err => {
        console.error('Redis connection failed:', err);
    });
}


const MPESA_BASE_URL = process.env.MPESA_BASE_URL || "https://sandbox.safaricom.co.ke";
const MPESA_SHORTCODE = process.env.MPESA_SHORTCODE;
const MPESA_PASSKEY = process.env.MPESA_PASSKEY;
const MPESA_CONSUMER_KEY = process.env.MPESA_CONSUMER_KEY;
const MPESA_CONSUMER_SECRET = process.env.MPESA_CONSUMER_SECRET;


const app = express();


app.use(express.json());
app.use(express.urlencoded({ extended: true }));



app.use((req, res, next) => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    next();
});



// Session configuration - works on both local and Vercel
app.use(session({
    store: process.env.NODE_ENV === 'production' && redisClient
        ? new RedisStore({ client: redisClient })
        : undefined, // Use memory store for local development
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // HTTPS only on Vercel
        sameSite: 'lax',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    },
    proxy: process.env.NODE_ENV === 'production' // Trust Vercel proxy
}));

function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect("/guestlogin");
    }
    next();
}

function requireAdmin(req, res, next) {
    console.log('Admin check:', {
        path: req.path,
        session: req.session,
        admin: req.session?.admin
    });

    if (!req.session.admin) {
        console.log('No admin session, redirecting to login');

        if (req.path.startsWith('/api/')) {
            return res.status(401).json({
                success: false,
                message: "Admin authentication required"
            });
        }

        return res.redirect("/adminlogin");
    }
    next();
}


app.use(cors({
    origin: true,
    credentials: true
}));





// Serve static files - works on both local and Vercel
const staticDirs = ['Styles', 'vid', 'images', 'icons'];
staticDirs.forEach(dir => {
    const dirPath = path.join(process.cwd(), dir);
    app.use(`/${dir}`, express.static(dirPath, {
        fallthrough: true // Don't error if directory doesn't exist
    }));
});


const htmlFiles = {
    "/": "index.html",
    "/roombooking": "roombooking.html",
    "/adminstatus": "admin.html",
    "/newsletter": "news.html",
    "/payment": "payment.html",
    "/profit": "profit.html",
    "/manageRooms": "adminaddroom.html",
    "/manageAdmins": "adminadd.html",
    "/homePage": "index.html",
    "/bookings": "roombooking.html",
    "/adminlogin": "Adminlogin.html",
    "/guestregistration": "register.html",
    "/guestlogin": "login.html",
    "/passwordreset": "forgot.html",
    "/reservation": "reservation.html",
    "/book-table": "table.html",
    "/activitystatus": "activity.html",
    "/frequentlyaskedquestions": "faq.html",
    "/notifications": "notifications.html",
    "/admin-simple": "admindashboard.html"
};


const publicPages = [
    "/", "/homePage", "/book-table", "/frequentlyaskedquestions",
    "/guestlogin", "/guestregistration", "/passwordreset",
    "/newsletter", "/adminlogin"
];


const userProtectedPages = [
    "/reservation",
    "/activitystatus",
    "/bookings",
    "/book-table",
    "/notifications"
];


const adminProtectedPages = [
    "/profit",
    "/manageRooms",
    "/manageAdmins",
    "/adminstatus",
    "/admin-simple",
    "/roombooking",
    "/payment"
];


// ============================================
// FIXED: Public Pages Routes - VERCEL COMPATIBLE
// ============================================
publicPages.forEach(route => {
    app.get(route, (req, res) => {
        const fileName = htmlFiles[route];

        if (!fileName) {
            console.error(`[Vercel] No file mapping for route: ${route}`);
            return res.status(404).send('Page not found');
        }

        // VERCEL FIX: Use process.cwd() instead of __dirname
        const filePath = path.join(process.cwd(), fileName);

        // Cache headers for login pages
        if (route === "/adminlogin" || route === "/guestlogin") {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }

        // Send file with error handling for Vercel
        res.sendFile(filePath, (err) => {
            if (err) {
                console.error(`[Vercel] Failed to send ${fileName}:`, err.message);

                // Try alternate paths for Vercel deployment
                if (err.code === 'ENOENT') {
                    const altPaths = [
                        path.join(process.cwd(), 'public', fileName),
                        path.join(process.cwd(), 'views', fileName),
                        path.join(process.cwd(), '..', fileName),
                        path.join(process.cwd(), '..', 'public', fileName)
                    ];

                    let attempt = 0;
                    function tryNextPath() {
                        if (attempt >= altPaths.length) {
                            return res.status(404).send(`Page ${route} not found`);
                        }

                        res.sendFile(altPaths[attempt], (altErr) => {
                            if (altErr) {
                                attempt++;
                                tryNextPath();
                            }
                        });
                    }
                    tryNextPath();
                } else {
                    res.status(500).send('Error loading page');
                }
            }
        });
    });
});

// ============================================
// FIXED: User Protected Pages Routes - VERCEL COMPATIBLE
// ============================================
userProtectedPages.forEach(route => {
    app.get(route, requireLogin, (req, res) => {
        const fileName = htmlFiles[route];

        if (!fileName) {
            console.error(`[Vercel] No file mapping for route: ${route}`);
            return res.status(404).send('Page not found');
        }

        // VERCEL FIX: Use process.cwd() instead of __dirname
        const filePath = path.join(process.cwd(), fileName);

        // Cache headers
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');

        // Send file with error handling for Vercel
        res.sendFile(filePath, (err) => {
            if (err) {
                console.error(`[Vercel] Failed to send protected file ${fileName}:`, err.message);

                // Try alternate paths for Vercel deployment
                if (err.code === 'ENOENT') {
                    const altPaths = [
                        path.join(process.cwd(), 'public', fileName),
                        path.join(process.cwd(), 'views', fileName),
                        path.join(process.cwd(), '..', fileName),
                        path.join(process.cwd(), '..', 'public', fileName)
                    ];

                    let attempt = 0;
                    function tryNextPath() {
                        if (attempt >= altPaths.length) {
                            return res.status(404).send(`Page ${route} not found`);
                        }

                        res.sendFile(altPaths[attempt], (altErr) => {
                            if (altErr) {
                                attempt++;
                                tryNextPath();
                            }
                        });
                    }
                    tryNextPath();
                } else {
                    res.status(500).send('Error loading page');
                }
            }
        });
    });
});

// ============================================
// FIXED: Admin Protected Pages Routes - VERCEL COMPATIBLE
// ============================================
adminProtectedPages.forEach(route => {
    app.get(route, requireAdmin, (req, res) => {
        const fileName = htmlFiles[route];

        if (!fileName) {
            console.error(`[Vercel] No file mapping for route: ${route}`);
            return res.status(404).send('Page not found');
        }

        // VERCEL FIX: Use process.cwd() instead of __dirname
        const filePath = path.join(process.cwd(), fileName);

        // Cache headers
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');

        // Send file with error handling for Vercel
        res.sendFile(filePath, (err) => {
            if (err) {
                console.error(`[Vercel] Failed to send admin file ${fileName}:`, err.message);

                // Try alternate paths for Vercel deployment
                if (err.code === 'ENOENT') {
                    const altPaths = [
                        path.join(process.cwd(), 'public', fileName),
                        path.join(process.cwd(), 'views', fileName),
                        path.join(process.cwd(), '..', fileName),
                        path.join(process.cwd(), '..', 'public', fileName)
                    ];

                    let attempt = 0;
                    function tryNextPath() {
                        if (attempt >= altPaths.length) {
                            return res.status(404).send(`Page ${route} not found`);
                        }

                        res.sendFile(altPaths[attempt], (altErr) => {
                            if (altErr) {
                                attempt++;
                                tryNextPath();
                            }
                        });
                    }
                    tryNextPath();
                } else {
                    res.status(500).send('Error loading page');
                }
            }
        });
    });
});

// ============================================
// FIXED: API Routes - VERCEL COMPATIBLE
// ============================================

/**
 * @route GET /api/session-user
 * @desc Get current session user data
 * @access Private
 */
app.get("/api/session-user", (req, res) => {
    try {
        // VERCEL FIX: Check if session exists and has user
        if (req.session && req.session.user) {
            return res.json({
                success: true,
                user: req.session.user
            });
        }
        return res.status(401).json({
            success: false,
            message: "Not logged in"
        });
    } catch (error) {
        console.error("[Vercel] Session user error:", error);
        res.status(500).json({
            success: false,
            message: "Session error"
        });
    }
});

/**
 * @route GET /api/admin/check
 * @desc Check if admin is logged in
 * @access Public
 */
app.get("/api/admin/check", (req, res) => {
    try {
        // VERCEL FIX: Add proper error handling
        if (req.session && req.session.admin) {
            return res.json({
                loggedIn: true,
                adminId: req.session.admin.adminId
            });
        }
        return res.json({
            loggedIn: false,
            message: "No admin session found"
        });
    } catch (error) {
        console.error("[Vercel] Admin check error:", error);
        res.status(500).json({
            loggedIn: false,
            message: "Session error"
        });
    }
});

/**
 * @route GET /api/user/check
 * @desc Check if user is logged in
 * @access Public
 */
app.get("/api/user/check", (req, res) => {
    try {
        // VERCEL FIX: Add proper error handling
        if (req.session && req.session.user) {
            return res.json({
                loggedIn: true,
                email: req.session.user.email,
                username: req.session.user.username,
                guest_id: req.session.user.guest_id
            });
        }
        return res.json({
            loggedIn: false,
            message: "No user session found"
        });
    } catch (error) {
        console.error("[Vercel] User check error:", error);
        res.status(500).json({
            loggedIn: false,
            message: "Session error"
        });
    }
});

// ============================================
// ADD THIS: 404 Handler for undefined routes
// ============================================
app.use((req, res, next) => {
    // Skip API routes
    if (req.path.startsWith('/api/')) {
        return next();
    }

    // Skip static files
    const staticExtensions = ['.css', '.js', '.jpg', '.png', '.gif', '.svg', '.ico', '.webp', '.json'];
    if (staticExtensions.some(ext => req.path.endsWith(ext))) {
        return next();
    }

    // Check if it's an HTML file request without extension
    const possibleHtmlFile = `${req.path.slice(1)}.html`;
    const filePath = path.join(process.cwd(), possibleHtmlFile);

    res.sendFile(filePath, (err) => {
        if (err) {
            // Try 404 page
            const notFoundPath = path.join(process.cwd(), '404.html');
            res.status(404).sendFile(notFoundPath, (notFoundErr) => {
                if (notFoundErr) {
                    res.status(404).send('Page not found');
                }
            });
        }
    });
});

// ============================================
// ADD THIS: Debug route to check file locations (REMOVE IN PRODUCTION)
// ============================================
if (process.env.NODE_ENV !== 'production') {
    app.get("/debug/paths", (req, res) => {
        res.json({
            cwd: process.cwd(),
            dirname: __dirname,
            files: Object.keys(htmlFiles).map(route => ({
                route,
                file: htmlFiles[route],
                exists: require('fs').existsSync(path.join(process.cwd(), htmlFiles[route]))
            }))
        });
    });
}


app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const [rows] = await db.execute(
            "SELECT * FROM guest WHERE email = ?",
            [email]
        );

        if (!rows.length) return res.status(401).json({ message: "Invalid credentials" });

        const guest = rows[0];


        const passwordMatch = await bcrypt.compare(password, guest.password);
        if (!passwordMatch) return res.status(401).json({ message: "Invalid credentials" });


        req.session.user = {
            guest_id: guest.guest_id,
            username: guest.username,
            email: guest.email
        };

        res.json({ success: true, message: "Logged in successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});


// ============================================
// FIXED: Admin Logout - VERCEL COMPATIBLE
// ============================================
app.get("/adminlogout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("[Vercel] Error destroying admin session:", err);

            // VERCEL FIX: Still try to clear cookies even if session destroy fails
            res.clearCookie("connect.sid", { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production' });
            res.clearCookie("session", { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production' });
            res.clearCookie("sessionId", { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production' });

            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');

            return res.redirect("/adminlogin");
        }

        // VERCEL FIX: Specify cookie options when clearing
        res.clearCookie("connect.sid", { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production' });
        res.clearCookie("session", { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production' });
        res.clearCookie("sessionId", { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production' });

        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');

        res.redirect("/adminlogin");
    });
});

// ============================================
// FIXED: User Logout - VERCEL COMPATIBLE
// ============================================
app.get("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("[Vercel] Error destroying user session:", err);

            // VERCEL FIX: Still try to clear cookies even if session destroy fails
            res.clearCookie("connect.sid", { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production' });
            res.clearCookie("session", { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production' });
            res.clearCookie("sessionId", { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production' });

            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');

            return res.redirect("/guestlogin");
        }

        // VERCEL FIX: Specify cookie options when clearing
        res.clearCookie("connect.sid", { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production' });
        res.clearCookie("session", { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production' });
        res.clearCookie("sessionId", { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production' });

        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');

        res.redirect("/guestlogin");
    });
});

// ============================================
// FIXED: Get User Reservations - VERCEL COMPATIBLE
// ============================================
app.get("/api/reservations", async (req, res) => {
    try {
        // VERCEL FIX: Check session with error handling
        if (!req.session || !req.session.user) {
            return res.status(401).json({
                success: false,
                message: "Not logged in"
            });
        }

        const email = req.session.user.email;

        // VERCEL FIX: Use async/await instead of callback
        const sql = `
            SELECT 
                r.reservation_id,
                r.room_type,
                r.bedding_type,
                r.no_of_rooms,
                r.meal_plan,
                r.check_in,
                r.check_out,
                r.roomTag,
                r.status AS reservation_status,
                r.total_amount,
                r.created_at,
                COALESCE(
                    (SELECT SUM(p2.amount_paid) 
                     FROM payments p2 
                     WHERE p2.reservation_id = r.reservation_id 
                     AND p2.status = 'Paid'), 
                0.00) AS amount_paid,
                (r.total_amount - COALESCE(
                    (SELECT SUM(p2.amount_paid) 
                     FROM payments p2 
                     WHERE p2.reservation_id = r.reservation_id 
                     AND p2.status = 'Paid'), 
                0.00)) AS amount_due,
                CASE 
                    WHEN EXISTS (
                        SELECT 1 FROM payments p3 
                        WHERE p3.reservation_id = r.reservation_id 
                        AND p3.status = 'Paid'
                    ) THEN 'Paid'
                    ELSE 'Pending'
                END AS payment_status,
                COALESCE(
                    (SELECT p4.payment_method 
                     FROM payments p4 
                     WHERE p4.reservation_id = r.reservation_id 
                     AND p4.status = 'Paid'
                     ORDER BY p4.payment_date DESC 
                     LIMIT 1), 
                NULL) AS payment_method,
                CASE 
                    WHEN r.status = 'Pending' 
                         AND NOT EXISTS (
                             SELECT 1 FROM payments p5 
                             WHERE p5.reservation_id = r.reservation_id 
                             AND p5.status = 'Paid'
                         )
                         AND TIMESTAMPDIFF(MINUTE, r.created_at, NOW()) >= 60
                         AND TIMESTAMPDIFF(MINUTE, r.created_at, NOW()) < 120
                    THEN TRUE 
                    ELSE FALSE 
                END AS needs_payment_reminder,
                CASE 
                    WHEN r.status = 'Pending' 
                         AND NOT EXISTS (
                             SELECT 1 FROM payments p6 
                             WHERE p6.reservation_id = r.reservation_id 
                             AND p6.status = 'Paid'
                         )
                         AND TIMESTAMPDIFF(MINUTE, r.created_at, NOW()) >= 120
                    THEN TRUE 
                    ELSE FALSE 
                END AS is_expired,
                CASE 
                    WHEN r.status = 'Pending' 
                         AND NOT EXISTS (
                             SELECT 1 FROM payments p7 
                             WHERE p7.reservation_id = r.reservation_id 
                             AND p7.status = 'Paid'
                         )
                         AND TIMESTAMPDIFF(MINUTE, r.created_at, NOW()) < 120
                    THEN 120 - TIMESTAMPDIFF(MINUTE, r.created_at, NOW())
                    ELSE NULL 
                END AS minutes_left
            FROM reservationsdetails r
            JOIN guestdetails gd ON r.guest_id = gd.guest_id
            WHERE gd.email = ?
            ORDER BY r.reservation_id DESC
        `;

        const [results] = await db.promise().query(sql, [email]);

        const formattedResults = results.map(reservation => {
            const minutesLeft = reservation.minutes_left;
            let timeLeftFormatted = null;

            if (minutesLeft !== null) {
                if (minutesLeft > 60) {
                    const hours = Math.floor(minutesLeft / 60);
                    const minutes = minutesLeft % 60;
                    timeLeftFormatted = `${hours} hour${hours > 1 ? 's' : ''} ${minutes > 0 ? `and ${minutes} minute${minutes > 1 ? 's' : ''}` : ''}`;
                } else {
                    timeLeftFormatted = `${minutesLeft} minute${minutesLeft > 1 ? 's' : ''}`;
                }
            }

            return {
                ...reservation,
                time_left_formatted: timeLeftFormatted,
                needs_payment_reminder: Boolean(reservation.needs_payment_reminder),
                is_expired: Boolean(reservation.is_expired),
                amount_paid: parseFloat(reservation.amount_paid || 0).toFixed(2),
                amount_due: parseFloat(reservation.amount_due || 0).toFixed(2),
                total_amount: parseFloat(reservation.total_amount || 0).toFixed(2)
            };
        });

        res.json({
            success: true,
            reservations: formattedResults
        });

    } catch (err) {
        console.error("[Vercel] Reservations fetch error:", err);
        res.status(500).json({
            success: false,
            message: "Database error",
            error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});

// ============================================
// FIXED: Get New Bookings (Admin) - VERCEL COMPATIBLE
// ============================================
app.get("/api/new-bookings", requireAdmin, async (req, res) => {
    try {
        const limit = req.query.limit;
        let sql = `
            SELECT 
                r.reservation_id,
                gd.first_name,
                gd.last_name,
                gd.email,
                gd.nationality,
                r.room_type,
                r.bedding_type,
                r.meal_plan,
                r.no_of_rooms,
                r.check_in,
                r.check_out,
                r.roomTag,
                r.status,
                r.total_amount,
                r.created_at,
                CASE 
                    WHEN r.no_of_rooms > 1 THEN CONCAT(r.no_of_rooms, ' rooms')
                    ELSE '1 room'
                END as rooms_display,
                COALESCE(
                    (SELECT p.status 
                     FROM payments p 
                     WHERE p.reservation_id = r.reservation_id 
                     ORDER BY p.payment_date DESC 
                     LIMIT 1), 
                'Pending') as payment_status
            FROM reservationsdetails r
            LEFT JOIN guestdetails gd ON r.guest_id = gd.guest_id
            ORDER BY r.created_at DESC
        `;

        const queryParams = [];
        if (limit && !isNaN(limit)) {
            sql += ` LIMIT ?`;
            queryParams.push(parseInt(limit));
        }

        const [results] = await db.promise().query(sql, queryParams);

        const enhancedResults = results.map(booking => {
            let roomCount = 1;
            if (booking.no_of_rooms) {
                roomCount = parseInt(booking.no_of_rooms) || 1;
            }

            let roomsArray = [];
            if (booking.roomTag) {
                if (typeof booking.roomTag === 'string' && booking.roomTag.includes(',')) {
                    roomsArray = booking.roomTag.split(',').map(r => r.trim());
                } else if (booking.roomTag) {
                    roomsArray = [booking.roomTag];
                }
            }

            return {
                ...booking,
                room_count: roomCount,
                rooms_array: roomsArray,
                has_multiple_rooms: roomCount > 1,
                guest_name: `${booking.first_name || ''} ${booking.last_name || ''}`.trim() || 'N/A',
                total_amount: parseFloat(booking.total_amount || 0).toFixed(2)
            };
        });

        res.json({
            success: true,
            bookings: enhancedResults
        });

    } catch (err) {
        console.error("[Vercel] Bookings fetch error:", err);
        res.status(500).json({
            success: false,
            error: "Database error",
            details: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});

// ============================================
// FIXED: Get Booked Rooms - VERCEL COMPATIBLE
// ============================================
app.get("/api/bookedRooms", async (req, res) => {
    try {
        const sql = `SELECT reservation_id, roomTag, room_type FROM reservationsdetails ORDER BY reservation_id DESC`;
        const [results] = await db.promise().query(sql);

        res.json({
            success: true,
            rooms: results
        });
    } catch (err) {
        console.error("[Vercel] BookedRooms error:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching booked rooms",
            error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});

// ============================================
// FIXED: Permit Reservation (Admin) - VERCEL COMPATIBLE
// ============================================
app.patch("/api/reservations/:id/permit", requireAdmin, async (req, res) => {
    const reservationId = req.params.id;
    let connection;

    try {
        // VERCEL FIX: Get connection from pool for transaction
        connection = await db.getConnection();
        await connection.beginTransaction();

        // Get reservation details
        const [reservationRows] = await connection.query(
            `SELECT r.reservation_id, r.guest_id, r.total_amount, 
                    gd.first_name, gd.last_name, gd.email
             FROM reservationsdetails r
             JOIN guestdetails gd ON r.guest_id = gd.guest_id
             WHERE r.reservation_id = ?`,
            [reservationId]
        );

        if (reservationRows.length === 0) {
            await connection.rollback();
            connection.release();
            return res.status(404).json({
                success: false,
                message: "Reservation not found"
            });
        }

        const reservation = reservationRows[0];
        const guestId = reservation.guest_id;
        const totalAmount = reservation.total_amount;
        const paymentMethod = 'Cash';

        console.log(`[Vercel] Permitting reservation ${reservationId} for guest ${guestId}, amount: ${totalAmount}`);

        // Check for existing payments
        const [existingPayments] = await connection.query(
            "SELECT payment_id FROM payments WHERE reservation_id = ?",
            [reservationId]
        );

        let paymentId;

        if (existingPayments.length > 0) {
            // Update existing payment
            await connection.query(
                `UPDATE payments 
                 SET status = 'Paid', 
                     amount_paid = ?,
                     payment_method = ?,
                     payment_date = NOW()
                 WHERE reservation_id = ?`,
                [totalAmount, paymentMethod, reservationId]
            );
            paymentId = existingPayments[0].payment_id;
            console.log(`[Vercel] Updated existing payment ${paymentId} to Paid`);
        } else {
            // Create new payment record
            const [paymentResult] = await connection.query(
                `INSERT INTO payments 
                 (reservation_id, guest_id, amount_paid, payment_method, status, payment_date)
                 VALUES (?, ?, ?, ?, 'Paid', NOW())`,
                [reservationId, guestId, totalAmount, paymentMethod]
            );
            paymentId = paymentResult.insertId;
            console.log(`[Vercel] Created new payment ${paymentId} with amount ${totalAmount}`);
        }

        // Update reservation status
        await connection.query(
            "UPDATE reservationsdetails SET status = 'Permitted' WHERE reservation_id = ?",
            [reservationId]
        );

        // Commit transaction
        await connection.commit();
        connection.release();

        res.json({
            success: true,
            message: "Reservation permitted and payment recorded successfully",
            reservationId: reservationId,
            paymentId: paymentId,
            paymentAmount: parseFloat(totalAmount).toFixed(2),
            paymentMethod: paymentMethod,
            guestName: `${reservation.first_name} ${reservation.last_name}`,
            guestEmail: reservation.email
        });

    } catch (err) {
        // VERCEL FIX: Proper error handling with transaction rollback
        console.error("[Vercel] Permit error:", err);

        if (connection) {
            await connection.rollback();
            connection.release();
        }

        res.status(500).json({
            success: false,
            message: "Server error",
            error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});

app.patch("/api/reservations/:id/reject", requireAdmin, async (req, res) => {
    const reservationId = req.params.id;
    try {
        const [result] = await db.promise().query(
            "UPDATE reservationsdetails SET status = 'Rejected' WHERE reservation_id = ?",
            [reservationId]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: "Reservation not found" });
        res.json({ message: "Reservation rejected successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});



app.post("/add-guest", async (req, res) => {
    const { username, email, password, confirmpassword } = req.body;
    if (!username || !email || !password || !confirmpassword)
        return res.status(400).send("All fields are required.");
    if (password !== confirmpassword) return res.status(400).send("Passwords do not match.");
    const emailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
    if (!emailRegex.test(email)) return res.status(400).send("Please enter a valid Gmail address.");

    try {
        const [results] = await db.promise().query("SELECT * FROM guest WHERE username = ?", [username]);
        if (results.length > 0) return res.status(400).send("Username already taken.");

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        await db.promise().query("INSERT INTO guest (username, email, password) VALUES (?, ?, ?)", [username, email, hashedPassword]);
        return res.redirect("/guestlogin");
    } catch (err) {
        console.error("Add guest error:", err);
        return res.status(500).send("Server error.");
    }
});

app.post("/guestlogin", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "All fields are required." });
    }

    const [results] = await db.promise().query(
        "SELECT * FROM guest WHERE email = ?",
        [email]
    );

    if (results.length === 0) {
        return res.status(400).json({ message: "No user found." });
    }

    const guest = results[0];
    const validPassword = await bcrypt.compare(password, guest.password);

    if (!validPassword) {
        return res.status(401).json({ message: "Incorrect password." });
    }

    req.session.user = {
        guest_id: guest.guest_id,
        username: guest.username,
        email: guest.email
    };


    const returnTo = req.session.returnTo || "/reservation";
    delete req.session.returnTo;

    res.json({ success: true, redirectTo: returnTo });
});


app.post("/loginGuest", async (req, res) => {
    const { email, password, rememberMe } = req.body;

    try {
        const [results] = await db.promise().query("SELECT * FROM guest WHERE email = ?", [email]);


        if (results.length === 0) return res.redirect("/guestlogin");

        const guest = results[0];
        const match = await bcrypt.compare(password, guest.password);


        if (!match) return res.redirect("/guestlogin");


        req.session.user = {
            guest_id: guest.guest_id,
            username: guest.username,
            email: guest.email
        };


        if (rememberMe) {
            req.session.cookie.maxAge = 7 * 24 * 60 * 60 * 1000;
        } else {
            req.session.cookie.expires = false;
        }

        return res.redirect("/reservation");

    } catch (error) {
        console.error(error);
        return res.redirect("/guestlogin");
    }
});



// ============================================
// FIXED: Get Guest Login Status - Enhanced - VERCEL COMPATIBLE
// ============================================
app.get("/api/guestlogin", (req, res) => {
    try {
        // VERCEL FIX: Comprehensive session check
        if (!req.session) {
            console.error("[Vercel] /api/guestlogin - Session is undefined");
            return res.status(500).json({
                success: false,
                message: "Session not initialized",
                code: "SESSION_MISSING"
            });
        }

        // Check if session contains user
        if (!req.session.user) {
            console.log("[Vercel] /api/guestlogin - No user in session");
            return res.status(401).json({
                success: false,
                message: "Not logged in",
                code: "NOT_LOGGED_IN"
            });
        }

        // VERCEL FIX: Validate user object has required fields
        const { guest_id, username, email } = req.session.user;

        if (!guest_id || !email) {
            console.error("[Vercel] /api/guestlogin - Invalid user object:", req.session.user);
            return res.status(500).json({
                success: false,
                message: "Invalid session data",
                code: "INVALID_SESSION"
            });
        }

        // Log successful authentication (useful for debugging)
        console.log(`[Vercel] /api/guestlogin - User authenticated: ${email}`);

        // Return user data
        res.json({
            success: true,
            guest_id: guest_id,
            username: username || '',
            email: email,
            // Add session ID for debugging (optional)
            sessionId: req.session.id
        });

    } catch (error) {
        console.error("[Vercel] /api/guestlogin - Error:", error);
        res.status(500).json({
            success: false,
            message: "Server error",
            code: "SERVER_ERROR",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});



app.post("/add-room", (req, res) => {
    const { roomTag, roomType } = req.body;
    if (!roomTag || !roomType) return res.status(400).send("Please select both room type and tag.");

    db.query(
        "INSERT INTO rooms (roomTag, roomType) VALUES (?, ?)",
        [roomTag, roomType],
        (err) => {
            if (err) {
                if (err.code === "ER_DUP_ENTRY") return res.status(400).send("Room Already Added.");
                console.error("Add room error:", err);
                return res.status(500).send("Error saving Room.");
            }
            res.send("Room saved successfully!");
        }
    );
});

// ============================================
// FIXED: Get All Rooms - VERCEL COMPATIBLE
// ============================================
app.get("/api/rooms", async (req, res) => {
    try {
        // VERCEL FIX: Convert callback to async/await
        const [results] = await db.promise().query(
            "SELECT * FROM rooms ORDER BY roomTag ASC"
        );

        // VERCEL FIX: Return consistent response format
        res.json({
            success: true,
            rooms: results,
            count: results.length
        });

    } catch (err) {
        console.error("[Vercel] Fetch rooms error:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching rooms",
            error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});

// ============================================
// FIXED: Admin Simple Dashboard Page - VERCEL COMPATIBLE
// ============================================
app.get("/admin-simple", requireAdmin, (req, res) => {
    try {
        // VERCEL FIX: Use process.cwd() instead of __dirname
        const fileName = "admin-simple.html";
        const filePath = path.join(process.cwd(), fileName);

        // Set cache headers
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');

        // Send file with error handling for Vercel
        res.sendFile(filePath, (err) => {
            if (err) {
                console.error(`[Vercel] Failed to send ${fileName}:`, err.message);

                // Try alternate paths for Vercel deployment
                if (err.code === 'ENOENT') {
                    const altPaths = [
                        path.join(process.cwd(), 'public', fileName),
                        path.join(process.cwd(), 'views', fileName),
                        path.join(process.cwd(), '..', fileName),
                        path.join(process.cwd(), '..', 'public', fileName)
                    ];

                    let attempt = 0;
                    function tryNextPath() {
                        if (attempt >= altPaths.length) {
                            return res.status(404).send(`Admin dashboard page not found`);
                        }

                        res.sendFile(altPaths[attempt], (altErr) => {
                            if (altErr) {
                                console.error(`[Vercel] Failed at path ${altPaths[attempt]}:`, altErr.message);
                                attempt++;
                                tryNextPath();
                            }
                        });
                    }
                    tryNextPath();
                } else {
                    res.status(500).send('Error loading admin dashboard');
                }
            }
        });

    } catch (error) {
        console.error("[Vercel] Admin-simple route error:", error);
        res.status(500).send('Server error');
    }
});

publicPages.push("/admin-simple");



app.delete("/api/bookedRooms/:reservationId", requireAdmin, async (req, res) => {
    const { reservationId } = req.params;

    try {

        const [bookingResult] = await db.promise().query(
            "SELECT roomTag FROM reservationsdetails WHERE reservation_id = ?",
            [reservationId]
        );

        if (bookingResult.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Reservation not found"
            });
        }

        const roomTag = bookingResult[0].roomTag;


        await db.promise().query(
            "DELETE FROM reservationsdetails WHERE reservation_id = ?",
            [reservationId]
        );


        await db.promise().query(
            "DELETE FROM payments WHERE reservation_id = ?",
            [reservationId]
        );

        console.log(` Deleted reservation ${reservationId} with room ${roomTag} from database`);

        res.json({
            success: true,
            message: "Booking deleted successfully from database",
            deletedReservationId: reservationId,
            deletedRoomTag: roomTag
        });

    } catch (err) {
        console.error("Delete booking error:", err);
        res.status(500).json({
            success: false,
            message: "Failed to delete booking from database"
        });
    }
});




app.post("/book-table", async (req, res) => {
    const { fullName, emailAddress, phoneNumber, bookingDate, bookingTime, guests, specialRequests } = req.body;

    if (!fullName || !emailAddress || !phoneNumber || !bookingDate || !bookingTime || !guests) {
        return res.status(400).json({ message: "Please fill all required fields." });
    }

    try {
        const sql = `
            INSERT INTO table_bookings
            (fullName, emailAddress, phoneNumber, bookingDate, bookingTime, guests, specialRequests)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        const [result] = await db.promise().query(sql, [fullName, emailAddress, phoneNumber, bookingDate, bookingTime, guests, specialRequests || null]);
        res.json({ message: "Table booked successfully!", bookingId: result.insertId });
    } catch (err) {
        console.error("Table booking error:", err);
        res.status(500).json({ message: "Database error", error: err.sqlMessage || err.message });
    }
});


// ============================================
// FIXED: Get All Table Bookings - VERCEL COMPATIBLE
// ============================================
app.get("/api/table-bookings", requireAdmin, async (req, res) => {
    try {
        // VERCEL FIX: Convert callback to async/await
        const sql = "SELECT * FROM table_bookings ORDER BY created_at DESC";
        const [results] = await db.promise().query(sql);

        // VERCEL FIX: Format dates and add computed fields
        const formattedResults = results.map(booking => ({
            ...booking,
            // Format dates for consistent display
            booking_date: booking.bookingDate ? new Date(booking.bookingDate).toISOString().split('T')[0] : null,
            booking_time: booking.bookingTime,
            created_at_formatted: booking.created_at ? new Date(booking.created_at).toLocaleString() : null,
            // Add full name for easy display
            full_name: booking.fullName || `${booking.firstName || ''} ${booking.lastName || ''}`.trim(),
            // Ensure guests is a number
            guests: parseInt(booking.guests) || 0,
            // Add status badge info
            status_badge: booking.status || 'pending',
            status_color: getTableBookingStatusColor(booking.status)
        }));

        res.json({
            success: true,
            bookings: formattedResults,
            count: formattedResults.length
        });

    } catch (err) {
        console.error("[Vercel] Fetch table bookings error:", err);
        res.status(500).json({
            success: false,
            message: "Database error",
            error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});

// Helper function for status colors (add this outside the route)
function getTableBookingStatusColor(status) {
    const colors = {
        'pending': 'yellow',
        'confirmed': 'green',
        'cancelled': 'red',
        'completed': 'blue'
    };
    return colors[status?.toLowerCase()] || 'gray';
}

app.delete("/api/table-bookings/:id", (req, res) => {
    const bookingId = req.params.id;
    const sql = "DELETE FROM table_bookings WHERE id = ?";
    db.query(sql, [bookingId], (err, result) => {
        if (err) {
            console.error("Delete table booking error:", err);
            return res.status(500).json({ message: "Database error" });
        }
        if (result.affectedRows === 0) return res.status(404).json({ message: "Booking not found" });
        res.json({ message: "Booking deleted successfully" });
    });
});




app.delete("/api/deleteRoom/:roomTag", (req, res) => {
    const roomTag = req.params.roomTag;


    const deleteRoomQuery = `
        DELETE FROM rooms
        WHERE roomTag = ?
    `;

    db.query(deleteRoomQuery, [roomTag], (err, roomResult) => {
        if (err) {
            console.error("Delete room error:", err);
            return res.status(500).json({ error: "Failed to delete room" });
        }

        if (roomResult.affectedRows === 0) {
            return res.status(404).json({ error: "Room not found" });
        }

        console.log(`Deleted room assignment: ${roomTag}`);

        res.json({
            success: true,
            deletedRoom: roomTag
        });
    });
});




app.post("/admin", async (req, res) => {
    const { adminId, adminPassword, action } = req.body;
    if (!adminId || !adminPassword || !action) return res.status(400).send("All fields are required.");

    if (action === "add") {
        try {
            const [adminResults] = await db.promise().query("SELECT * FROM admin WHERE adminId = ?", [adminId]);
            if (adminResults.length > 0) return res.status(400).send("Admin already exists.");
            const hashedPassword = await bcrypt.hash(adminPassword, SALT_ROUNDS);
            await db.promise().query("INSERT INTO admin (adminId, adminPassword) VALUES (?, ?)", [adminId, hashedPassword]);
            res.send("Admin added successfully!");
        } catch (err) {
            console.error("Admin add error:", err);
            res.status(500).send("Error saving admin.");
        }
    } else if (action === "delete") {
        try {
            const [results] = await db.promise().query("SELECT adminPassword FROM admin WHERE adminId = ?", [adminId]);
            if (results.length === 0) return res.status(404).send("No matching admin found.");
            const passwordIsValid = await bcrypt.compare(adminPassword, results[0].adminPassword);
            if (!passwordIsValid) return res.status(401).send("Invalid credentials.");
            await db.promise().query("DELETE FROM admin WHERE adminId = ?", [adminId]);
            res.send("Admin deleted successfully!");
        } catch (err) {
            console.error("Admin delete error:", err);
            res.status(500).send("Error deleting admin.");
        }
    } else {
        res.status(400).send("Invalid action. Use 'add' or 'delete'.");
    }
});


app.post("/loginAdmin", async (req, res) => {
    const { adminId, adminPassword, rememberMe } = req.body;


    if (!adminId || !adminPassword) {
        return res.redirect("/adminlogin");
    }

    try {
        const [results] = await db.promise().query("SELECT * FROM admin WHERE adminId = ?", [adminId]);


        if (results.length === 0) {
            return res.redirect("/adminlogin");
        }

        const admin = results[0];
        const match = await bcrypt.compare(adminPassword, admin.adminPassword);


        if (!match) {
            return res.redirect("/adminlogin");
        }


        req.session.admin = {
            adminId: admin.adminId
        };

        if (rememberMe) {
            req.session.cookie.maxAge = 7 * 24 * 60 * 60 * 1000;
        } else {
            req.session.cookie.expires = false;
        }

        const returnTo = req.session.returnTo || "/admin-simple";
        delete req.session.returnTo;

        return res.redirect(returnTo);

    } catch (err) {
        console.error("Admin login error:", err);

        return res.redirect("/adminlogin");
    }
});

app.post("/subscribe", (req, res) => {
    const { fullName, phoneNumber, emailAddress } = req.body;
    if (!fullName || !emailAddress) return res.status(400).json({ message: "Name and email are required." });

    const checkQuery = "SELECT * FROM newsletter WHERE email = ?";
    db.query(checkQuery, [emailAddress], (err, results) => {
        if (err) return res.status(500).json({ message: "Database error." });
        if (results.length > 0) return res.json({ message: "This email is already subscribed." });

        const insertQuery = `
      INSERT INTO newsletter (name, phone, email, status, date_subscribed)
      VALUES (?, ?, ?, 'Pending', NOW())
    `;
        db.query(insertQuery, [fullName, phoneNumber, emailAddress], (err2) => {
            if (err2) return res.status(500).json({ message: "Failed to subscribe." });
            res.json({ message: "Subscribed successfully! Awaiting admin approval." });
        });
    });
});

require('dotenv').config();
const { MailerSend, EmailParams } = require("mailersend");

const mailersend = new MailerSend({
    api_key: process.env.MAILERSEND_API_KEY
});


app.post("/admin/sendNewsletter", async (req, res) => {
    const { subject, message } = req.body;
    if (!subject || !message) return res.json({ message: "Both subject and message are required." });

    try {

        const [subscribers] = await db.promise().query("SELECT email FROM newsletter WHERE status = 'Permitted'");
        if (subscribers.length === 0) return res.json({ message: "No subscribers to send to." });

        let successCount = 0;
        let failedList = [];

        for (const sub of subscribers) {
            try {
                await mailersend.email.send({
                    from: process.env.FROM_EMAIL,
                    to: [sub.email],
                    subject,
                    html: `<p>${message}</p>`
                });
                successCount++;
            } catch (err) {
                console.error("Failed to send to", sub.email, err?.response?.data || err);
                failedList.push(sub.email);
            }

        }

        res.json({
            message: `Newsletter sent to ${successCount} subscribers.`,
            failed: failedList
        });

    } catch (err) {
        console.error("Newsletter send error:", err);
        res.status(500).json({ message: "Failed to send newsletter." });
    }
});


// ============================================
// FIXED: Get Newsletter Subscribers - VERCEL COMPATIBLE
// ============================================
app.get("/admin/subscribers", requireAdmin, async (req, res) => {
    try {
        // VERCEL FIX: Convert callback to async/await
        const sql = "SELECT * FROM newsletter ORDER BY date_subscribed DESC";
        const [results] = await db.promise().query(sql);

        // VERCEL FIX: Format dates and add computed fields
        const formattedResults = results.map(subscriber => ({
            id: subscriber.id,
            name: subscriber.name || subscriber.fullName || '',
            phone: subscriber.phone || subscriber.phoneNumber || '',
            email: subscriber.email,
            status: subscriber.status || 'Pending',
            // Format dates for consistent display
            date_subscribed: subscriber.date_subscribed
                ? new Date(subscriber.date_subscribed).toISOString().split('T')[0]
                : null,
            date_subscribed_formatted: subscriber.date_subscribed
                ? new Date(subscriber.date_subscribed).toLocaleString()
                : null,
            // Add status badge color
            status_color: getSubscriberStatusColor(subscriber.status),
            // Add timestamp for sorting
            timestamp: subscriber.date_subscribed ? new Date(subscriber.date_subscribed).getTime() : 0
        }));

        res.json({
            success: true,
            subscribers: formattedResults,
            count: formattedResults.length,
            pending_count: formattedResults.filter(s => s.status?.toLowerCase() === 'pending').length,
            permitted_count: formattedResults.filter(s => s.status?.toLowerCase() === 'permitted').length
        });

    } catch (err) {
        console.error("[Vercel] Fetch subscribers error:", err);

        // VERCEL FIX: Return empty array with error info instead of just []
        res.status(500).json({
            success: false,
            subscribers: [],
            count: 0,
            message: "Failed to fetch subscribers",
            error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});

// Helper function for status colors
function getSubscriberStatusColor(status) {
    const colors = {
        'pending': 'yellow',
        'permitted': 'green',
        'approved': 'green',
        'rejected': 'red',
        'unsubscribed': 'gray'
    };
    return colors[status?.toLowerCase()] || 'gray';
}

app.delete("/admin/subscribers/:id", (req, res) => {
    const id = req.params.id;
    db.query("DELETE FROM newsletter WHERE id = ?", [id], (err) => {
        if (err) return res.json({ message: "Failed to delete subscriber." });
        res.json({ message: "Subscriber deleted successfully!" });
    });
});


app.put("/admin/subscribers/approve/:id", (req, res) => {
    const id = req.params.id;
    db.query("UPDATE newsletter SET status = 'Permitted' WHERE id = ?", [id], (err) => {
        if (err) return res.json({ message: "Failed to update subscriber status." });
        res.json({ message: "Subscriber approved successfully!" });
    });
});


app.post('/forgotpassword', async (req, res) => {
    const { email } = req.body;

    const [users] = await db.promise().query("SELECT * FROM guest WHERE email = ?", [email]);
    if (users.length === 0) return res.status(400).json({ message: "No user found with this email." });

    const token = jwt.sign({ email }, SESSION_SECRET, { expiresIn: '1h' });
    const resetLink = `http://localhost:3000/resetpassword/${token}`;

    try {
        await mailersend.email.send({
            from: {
                email: process.env.FROM_EMAIL,
                name: "Your Hotel Name"
            },
            to: [
                { email }
            ],
            subject: "Password Reset",
            html: `<p>Click <a href="${resetLink}">here</a> to reset your password. Link expires in 1 hour.</p>`
        });

        res.status(200).json({ message: "Password reset link sent!" });
    } catch (err) {
        console.error("Forgot password email error:", err?.response?.data || err);
        res.status(500).json({ message: "Failed to send password reset email." });
    }
});




app.post("/resetpassword/:token", async (req, res) => {
    const { token } = req.params;
    const { newPassword, confirmPassword } = req.body;

    if (!newPassword || !confirmPassword) return res.status(400).json({ message: "All fields are required" });
    if (newPassword !== confirmPassword) return res.status(400).json({ message: "Passwords do not match" });

    try {

        const decoded = jwt.verify(token, SESSION_SECRET);
        const email = decoded.email;

        const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
        await db.promise().query("UPDATE guest SET password=? WHERE email=?", [hashedPassword, email]);

        res.json({ message: "Password updated successfully!" });
    } catch (err) {
        console.error("Reset password error:", err);
        res.status(400).json({ message: "Invalid or expired token." });
    }
});




app.post("/book-room", async (req, res) => {
    try {
        console.log("BOOK-ROOM REQUEST BODY:", req.body);

        if (!req.session.user) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const email = req.session.user.email;

        const {
            roomType,
            beddingType,
            noOfRooms,
            mealPlan,
            checkIn,
            checkOut,
            roomTag,
            roomTags
        } = req.body;


        if (
            !roomType || !beddingType || !noOfRooms ||
            !mealPlan || !checkIn || !checkOut
        ) {
            return res.status(400).json({
                message: "All reservation fields are required."
            });
        }


        let roomTagValue;
        if (roomTags && Array.isArray(roomTags) && roomTags.length > 0) {
            roomTagValue = roomTags.join(', ');
        } else if (roomTag) {
            roomTagValue = roomTag;
        } else {
            return res.status(400).json({
                message: "Room tag is required."
            });
        }

        const roomPrice = parseInt(roomType) || 0;
        const beddingPrice = parseInt(beddingType) || 0;
        const mealPrice = parseInt(mealPlan) || 0;
        const roomsCount = parseInt(noOfRooms) || 1;


        const checkInDate = new Date(checkIn);
        const checkOutDate = new Date(checkOut);
        const nights = Math.max(1, Math.floor((checkOutDate - checkInDate) / (1000 * 60 * 60 * 24)));


        const totalAmount = (roomPrice + beddingPrice + mealPrice) * roomsCount * nights;


        const [guestRow] = await db.promise().query(
            "SELECT guest_id FROM guestdetails WHERE email = ? LIMIT 1",
            [email]
        );

        if (!guestRow.length) {
            return res.status(400).json({
                message: "Please save your personal details before booking."
            });
        }

        const guestId = guestRow[0].guest_id;


        const insertReservationSql = `
            INSERT INTO reservationsdetails
            (
                guest_id,
                room_type,
                bedding_type,
                no_of_rooms,
                meal_plan,
                check_in,
                check_out,
                roomTag,
                total_amount,
                nights,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', NOW())
        `;

        console.log("SQL Parameters:", [
            guestId,
            roomType,
            beddingType,
            noOfRooms,
            mealPlan,
            checkIn,
            checkOut,
            roomTagValue,
            totalAmount,
            nights
        ]);

        const [reservationResult] = await db.promise().query(
            insertReservationSql,
            [
                guestId,
                roomType,
                beddingType,
                noOfRooms,
                mealPlan,
                checkIn,
                checkOut,
                roomTagValue,
                totalAmount,
                nights
            ]
        );

        res.status(201).json({
            success: true,
            message: "Reservation created successfully.",
            reservationId: reservationResult.insertId,
            totalAmount: totalAmount,
            nights: nights
        });

    } catch (error) {
        console.error("Book Room Error:", error);
        res.status(500).json({
            success: false,
            message: "Server error while booking room."
        });
    }
});


app.put("/api/guestdetails/update", async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const email = req.session.user.email;

        const {
            title,
            first_name,
            last_name,
            nationality,
            passport_country,
            national_id,
            passport_no,
            phone_number
        } = req.body;

        const updateSql = `
            UPDATE guestdetails
            SET
                title = ?,
                first_name = ?,
                last_name = ?,
                nationality = ?,
                passport_country = ?,
                national_id = ?,
                passport_no = ?,
                phone_number = ?
            WHERE email = ?
        `;

        await db.promise().query(updateSql, [
            title,
            first_name,
            last_name,
            nationality,
            passport_country || null,
            national_id || null,
            passport_no || null,
            phone_number,
            email
        ]);

        res.json({ message: "Personal details updated successfully." });

    } catch (error) {
        console.error("Update Guest Error:", error);
        res.status(500).json({ message: "Failed to update guest details." });
    }
});


app.post("/api/guestdetails/save", async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const email = req.session.user.email;

        const {
            title,
            first_name,
            last_name,
            nationality,
            passport_country,
            national_id,
            passport_no,
            phone_number
        } = req.body;

        const insertSql = `
            INSERT INTO guestdetails
            (
                email,
                title,
                first_name,
                last_name,
                nationality,
                passport_country,
                national_id,
                passport_no,
                phone_number
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        await db.promise().query(insertSql, [
            email,
            title,
            first_name,
            last_name,
            nationality,
            passport_country || null,
            national_id || null,
            passport_no || null,
            phone_number
        ]);

        res.json({ message: "Personal details saved successfully." });

    } catch (error) {
        console.error("Save Guest Error:", error);
        res.status(500).json({ message: "Failed to save guest details." });
    }
});




// ============================================
// FIXED: Dashboard Recent Bookings - VERCEL COMPATIBLE
// ============================================
app.get("/api/dashboard/recent-bookings", requireAdmin, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 5;

        const query = `
            SELECT 
                r.reservation_id,
                gd.first_name,
                gd.last_name,
                gd.email,
                gd.nationality,
                r.room_type,
                r.bedding_type,
                r.meal_plan,
                r.no_of_rooms,
                r.check_in,
                r.check_out,
                r.roomTag,
                r.status,
                r.total_amount,
                r.created_at,
                COALESCE(
                    (SELECT p.status 
                     FROM payments p 
                     WHERE p.reservation_id = r.reservation_id 
                     ORDER BY p.payment_date DESC 
                     LIMIT 1), 
                'Pending') as payment_status,
                COALESCE(
                    (SELECT SUM(p2.amount_paid) 
                     FROM payments p2 
                     WHERE p2.reservation_id = r.reservation_id 
                     AND p2.status = 'Paid'), 
                0.00) AS amount_paid
            FROM reservationsdetails r
            LEFT JOIN guestdetails gd ON r.guest_id = gd.guest_id
            WHERE r.check_out >= CURDATE()
            ORDER BY r.created_at DESC
            LIMIT ?
        `;

        const [results] = await db.promise().query(query, [limit]);

        const roomTypeMap = {
            '5000': 'Standard',
            '7500': 'Deluxe',
            '12000': 'Suite',
            '18000': 'Family Suite'
        };

        const bookings = results.map(booking => {
            // Calculate room count from roomTag
            let roomCount = 1;
            let roomsArray = [];
            if (booking.roomTag) {
                roomsArray = booking.roomTag.split(',').map(r => r.trim()).filter(r => r);
                roomCount = roomsArray.length;
            }

            // VERCEL FIX: Proper date handling for serverless
            const checkIn = booking.check_in ? new Date(booking.check_in) : null;
            const checkOut = booking.check_out ? new Date(booking.check_out) : null;
            const today = new Date();
            today.setHours(0, 0, 0, 0);

            return {
                reservation_id: booking.reservation_id,
                guest_name: `${booking.first_name || ''} ${booking.last_name || ''}`.trim() || 'N/A',
                guest_email: booking.email,
                nationality: booking.nationality || 'N/A',
                room_type: booking.room_type,
                room_type_label: roomTypeMap[booking.room_type] || `Room Type ${booking.room_type}`,
                bedding_type: booking.bedding_type,
                meal_plan: booking.meal_plan,
                no_of_rooms: booking.no_of_rooms || 1,
                room_count: roomCount,
                rooms_array: roomsArray,
                rooms_display: booking.roomTag || 'Not assigned',
                check_in: checkIn ? checkIn.toISOString().split('T')[0] : null,
                check_out: checkOut ? checkOut.toISOString().split('T')[0] : null,
                status: booking.status || 'Pending',
                payment_status: booking.payment_status || 'Pending',
                total_amount: parseFloat(booking.total_amount || 0).toFixed(2),
                amount_paid: parseFloat(booking.amount_paid || 0).toFixed(2),
                amount_due: (parseFloat(booking.total_amount || 0) - parseFloat(booking.amount_paid || 0)).toFixed(2),
                booking_date: booking.created_at ? new Date(booking.created_at).toISOString() : null,
                booking_date_formatted: booking.created_at ? new Date(booking.created_at).toLocaleString() : null,
                is_active: checkOut ? checkOut >= today : false,
                nights: checkIn && checkOut ? Math.max(1, Math.ceil((checkOut - checkIn) / (1000 * 60 * 60 * 24))) : 0
            };
        });

        res.json({
            success: true,
            bookings: bookings,
            count: bookings.length,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('[Vercel] Error fetching recent bookings:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch recent bookings',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// FIXED: Available Rooms - VERCEL COMPATIBLE
// ============================================
app.get("/api/available-rooms", async (req, res) => {
    try {
        const { checkIn, checkOut } = req.query;

        if (!checkIn || !checkOut) {
            return res.status(400).json({
                success: false,
                message: "Check-in and check-out dates are required"
            });
        }

        // VERCEL FIX: Validate date format
        const checkInDate = new Date(checkIn);
        const checkOutDate = new Date(checkOut);

        if (isNaN(checkInDate.getTime()) || isNaN(checkOutDate.getTime())) {
            return res.status(400).json({
                success: false,
                message: "Invalid date format"
            });
        }

        // Query to find booked rooms
        const query = `
            SELECT roomTag 
            FROM reservationsdetails 
            WHERE (
                (status = 'Permitted')
                OR 
                (status = 'Pending' AND created_at >= DATE_SUB(NOW(), INTERVAL 2 HOUR))
            )
            AND (
                (check_in <= ? AND check_out >= ?) OR
                (check_in <= ? AND check_out >= ?) OR
                (check_in >= ? AND check_out <= ?)
            )
            AND roomTag IS NOT NULL
            AND roomTag != ''
        `;

        const [bookedReservations] = await db.promise().query(query, [
            checkOut, checkIn,
            checkIn, checkOut,
            checkIn, checkOut
        ]);

        // VERCEL FIX: Use Set for unique room tags
        const bookedTags = new Set();

        bookedReservations.forEach(reservation => {
            if (reservation.roomTag) {
                reservation.roomTag.split(',')
                    .map(tag => tag.trim())
                    .filter(tag => tag)
                    .forEach(tag => bookedTags.add(tag));
            }
        });

        // Get all rooms
        const [allRooms] = await db.promise().query(
            "SELECT roomTag, roomType FROM rooms ORDER BY roomTag ASC"
        );

        // Create room status array
        const roomStatus = allRooms.map(room => ({
            roomTag: room.roomTag,
            roomType: room.roomType,
            isAvailable: !bookedTags.has(room.roomTag)
        }));

        // VERCEL FIX: Group by availability for easier frontend use
        const availableRoomsList = roomStatus.filter(room => room.isAvailable).map(r => r.roomTag);
        const bookedRoomsList = Array.from(bookedTags);

        res.json({
            success: true,
            bookedRooms: bookedRoomsList,
            availableRooms: availableRoomsList,
            roomStatus: roomStatus,
            stats: {
                totalRooms: allRooms.length,
                bookedRooms: bookedTags.size,
                availableRooms: allRooms.length - bookedTags.size,
                occupancyRate: allRooms.length > 0 ? Math.round((bookedTags.size / allRooms.length) * 100) : 0
            },
            dateRange: {
                checkIn: checkIn,
                checkOut: checkOut
            }
        });

    } catch (error) {
        console.error('[Vercel] Error fetching room availability:', error);
        res.status(500).json({
            success: false,
            message: "Failed to check room availability",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// FIXED: Single Room Availability - VERCEL COMPATIBLE
// ============================================
app.get("/api/room-availability/:roomTag", async (req, res) => {
    try {
        const { roomTag } = req.params;
        const { checkIn, checkOut } = req.query;

        if (!roomTag || !checkIn || !checkOut) {
            return res.status(400).json({
                success: false,
                message: "Room tag, check-in and check-out dates are required"
            });
        }

        // VERCEL FIX: Validate dates
        const checkInDate = new Date(checkIn);
        const checkOutDate = new Date(checkOut);

        if (isNaN(checkInDate.getTime()) || isNaN(checkOutDate.getTime())) {
            return res.status(400).json({
                success: false,
                message: "Invalid date format"
            });
        }

        // Query to check if room is booked
        const query = `
            SELECT COUNT(*) as count 
            FROM reservationsdetails 
            WHERE (
                (status = 'Permitted')
                OR 
                (status = 'Pending' AND created_at >= DATE_SUB(NOW(), INTERVAL 2 HOUR))
            )
            AND (
                (check_in <= ? AND check_out >= ?) OR
                (check_in <= ? AND check_out >= ?) OR
                (check_in >= ? AND check_out <= ?)
            )
            AND (
                roomTag = ? 
                OR FIND_IN_SET(?, REPLACE(roomTag, ' ', ''))
                OR roomTag LIKE CONCAT(?, ',%')
                OR roomTag LIKE CONCAT('%, ', ?)
                OR roomTag LIKE CONCAT('%,', ?)
                OR roomTag LIKE CONCAT('%, ', ?, ',%')
            )
        `;

        const [result] = await db.promise().query(query, [
            checkOut, checkIn,
            checkIn, checkOut,
            checkIn, checkOut,
            roomTag,
            roomTag,
            roomTag,
            roomTag,
            roomTag,
            roomTag
        ]);

        const bookedCount = parseInt(result[0].count) || 0;
        const isAvailable = bookedCount === 0;

        // VERCEL FIX: Get room details
        const [roomDetails] = await db.promise().query(
            "SELECT roomType FROM rooms WHERE roomTag = ?",
            [roomTag]
        );

        res.json({
            success: true,
            roomTag: roomTag,
            roomType: roomDetails[0]?.roomType || null,
            isAvailable: isAvailable,
            bookedCount: bookedCount,
            availability: isAvailable ? 'available' : 'booked',
            dateRange: {
                checkIn: checkIn,
                checkOut: checkOut
            }
        });

    } catch (error) {
        console.error('[Vercel] Error checking room availability:', error);
        res.status(500).json({
            success: false,
            message: "Failed to check room availability",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// FIXED: Get Payment Details - VERCEL COMPATIBLE
// ============================================
app.get("/api/payment/:reservationId", async (req, res) => {
    try {
        const { reservationId } = req.params;

        // VERCEL FIX: Validate reservation ID
        if (!reservationId || isNaN(parseInt(reservationId))) {
            return res.status(400).json({
                success: false,
                message: "Invalid reservation ID"
            });
        }

        const sql = `
            SELECT
                r.reservation_id,
                r.room_type,
                r.bedding_type,
                r.no_of_rooms,
                r.meal_plan,
                r.check_in,
                r.check_out,
                r.roomTag,
                r.total_amount,
                r.status as reservation_status,
                COALESCE(
                    (SELECT SUM(p2.amount_paid) 
                     FROM payments p2 
                     WHERE p2.reservation_id = r.reservation_id 
                     AND p2.status = 'Paid'), 
                0.00) AS amount_paid,
                COALESCE(
                    (SELECT p3.status 
                     FROM payments p3 
                     WHERE p3.reservation_id = r.reservation_id 
                     ORDER BY p3.payment_date DESC 
                     LIMIT 1), 
                'Pending') AS payment_status,
                COALESCE(
                    (SELECT p4.payment_method 
                     FROM payments p4 
                     WHERE p4.reservation_id = r.reservation_id 
                     ORDER BY p4.payment_date DESC 
                     LIMIT 1), 
                NULL) AS payment_method,
                COALESCE(
                    (SELECT p5.payment_date 
                     FROM payments p5 
                     WHERE p5.reservation_id = r.reservation_id 
                     AND p5.status = 'Paid'
                     ORDER BY p5.payment_date DESC 
                     LIMIT 1), 
                NULL) AS last_payment_date,
                COALESCE(
                    (SELECT p6.mpesa_receipt 
                     FROM payments p6 
                     WHERE p6.reservation_id = r.reservation_id 
                     AND p6.mpesa_receipt IS NOT NULL
                     ORDER BY p6.payment_date DESC 
                     LIMIT 1), 
                NULL) AS mpesa_receipt
            FROM reservationsdetails r
            WHERE r.reservation_id = ?
        `;

        const [results] = await db.promise().query(sql, [reservationId]);

        if (results.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Reservation not found."
            });
        }

        const payment = results[0];

        // VERCEL FIX: Calculate amount due and format currency
        const totalAmount = parseFloat(payment.total_amount || 0);
        const amountPaid = parseFloat(payment.amount_paid || 0);
        const amountDue = totalAmount - amountPaid;

        // VERCEL FIX: Format dates
        const formattedPayment = {
            ...payment,
            total_amount: totalAmount.toFixed(2),
            amount_paid: amountPaid.toFixed(2),
            amount_due: amountDue.toFixed(2),
            check_in: payment.check_in ? new Date(payment.check_in).toISOString().split('T')[0] : null,
            check_out: payment.check_out ? new Date(payment.check_out).toISOString().split('T')[0] : null,
            last_payment_date: payment.last_payment_date ? new Date(payment.last_payment_date).toISOString() : null,
            last_payment_date_formatted: payment.last_payment_date ? new Date(payment.last_payment_date).toLocaleString() : null,
            is_fully_paid: amountDue <= 0,
            payment_progress: totalAmount > 0 ? Math.round((amountPaid / totalAmount) * 100) : 0
        };

        res.json({
            success: true,
            payment: formattedPayment
        });

    } catch (err) {
        console.error('[Vercel] Payment fetch error:', err);
        res.status(500).json({
            success: false,
            message: "Database error.",
            error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});


app.put("/api/payment/:paymentId/status", (req, res) => {
    const { paymentId } = req.params;
    const { status } = req.body;
    if (!status) return res.status(400).json({ message: "Status is required." });

    const sql = `UPDATE payments SET status = ? WHERE payment_id = ?`;

    db.query(sql, [status, paymentId], (err, result) => {
        if (err) {
            console.error("update payment status error:", err);
            return res.status(500).json({ message: "Database error." });
        }
        if (result.affectedRows === 0) return res.status(404).json({ message: "Payment not found." });
        res.json({ message: "Payment status updated successfully." });
    });
});


// ============================================
// FIXED: Get Single Reservation Details - VERCEL COMPATIBLE
// ============================================
app.get("/api/reservations/:id", async (req, res) => {
    try {
        const { id } = req.params;

        // VERCEL FIX: Validate reservation ID
        if (!id || isNaN(parseInt(id))) {
            return res.status(400).json({
                success: false,
                message: "Invalid reservation ID"
            });
        }

        const reservationId = parseInt(id);

        // VERCEL FIX: Enhanced query with better payment aggregation
        const sql = `
            SELECT 
                r.reservation_id,
                r.room_type,
                r.bedding_type,
                r.no_of_rooms,
                r.meal_plan,
                r.check_in,
                r.check_out,
                r.roomTag,
                r.status AS reservation_status,
                r.total_amount,
                r.nights,
                r.created_at,
                
                -- Guest details
                g.title,
                g.first_name,
                g.last_name,
                g.email,
                g.nationality,
                g.passport_country,
                g.phone_number,
                g.national_id,
                g.passport_no,
                
                -- Payment summary
                COALESCE(SUM(CASE WHEN p.status = 'Paid' THEN p.amount_paid ELSE 0 END), 0.00) AS amount_paid,
                COUNT(DISTINCT CASE WHEN p.status = 'Paid' THEN p.payment_id END) AS payment_count,
                
                -- Latest payment details
                (
                    SELECT p2.status 
                    FROM payments p2 
                    WHERE p2.reservation_id = r.reservation_id 
                    ORDER BY p2.payment_date DESC 
                    LIMIT 1
                ) AS payment_status,
                (
                    SELECT p3.payment_method 
                    FROM payments p3 
                    WHERE p3.reservation_id = r.reservation_id 
                    ORDER BY p3.payment_date DESC 
                    LIMIT 1
                ) AS payment_method,
                (
                    SELECT p4.payment_date 
                    FROM payments p4 
                    WHERE p4.reservation_id = r.reservation_id 
                    AND p4.status = 'Paid'
                    ORDER BY p4.payment_date DESC 
                    LIMIT 1
                ) AS last_payment_date,
                (
                    SELECT p5.mpesa_receipt 
                    FROM payments p5 
                    WHERE p5.reservation_id = r.reservation_id 
                    AND p5.mpesa_receipt IS NOT NULL
                    ORDER BY p5.payment_date DESC 
                    LIMIT 1
                ) AS mpesa_receipt
                
            FROM reservationsdetails r
            LEFT JOIN guestdetails g ON r.guest_id = g.guest_id
            LEFT JOIN payments p ON r.reservation_id = p.reservation_id
            WHERE r.reservation_id = ?
            GROUP BY r.reservation_id
            LIMIT 1
        `;

        const [results] = await db.promise().query(sql, [reservationId]);

        if (results.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Reservation not found"
            });
        }

        const reservation = results[0];

        // VERCEL FIX: Calculate financial summary
        const totalAmount = parseFloat(reservation.total_amount || 0);
        const amountPaid = parseFloat(reservation.amount_paid || 0);
        const amountDue = totalAmount - amountPaid;
        const paymentProgress = totalAmount > 0 ? Math.round((amountPaid / totalAmount) * 100) : 0;

        // VERCEL FIX: Calculate stay duration
        let nights = reservation.nights || 0;
        if (!nights && reservation.check_in && reservation.check_out) {
            const checkIn = new Date(reservation.check_in);
            const checkOut = new Date(reservation.check_out);
            nights = Math.max(1, Math.ceil((checkOut - checkIn) / (1000 * 60 * 60 * 24)));
        }

        // VERCEL FIX: Parse room tags
        let roomTags = [];
        let roomCount = 1;
        if (reservation.roomTag) {
            roomTags = reservation.roomTag.split(',').map(tag => tag.trim()).filter(tag => tag);
            roomCount = roomTags.length;
        }

        // VERCEL FIX: Format dates for consistent display
        const formattedReservation = {
            // Reservation details
            reservation_id: reservation.reservation_id,
            room_type: reservation.room_type,
            bedding_type: reservation.bedding_type,
            no_of_rooms: parseInt(reservation.no_of_rooms || roomCount || 1),
            meal_plan: reservation.meal_plan,
            roomTag: reservation.roomTag,
            room_tags: roomTags,
            room_count: roomCount,

            // Dates
            check_in: reservation.check_in ? new Date(reservation.check_in).toISOString().split('T')[0] : null,
            check_in_formatted: reservation.check_in ? new Date(reservation.check_in).toLocaleDateString() : null,
            check_out: reservation.check_out ? new Date(reservation.check_out).toISOString().split('T')[0] : null,
            check_out_formatted: reservation.check_out ? new Date(reservation.check_out).toLocaleDateString() : null,
            nights: nights,
            created_at: reservation.created_at ? new Date(reservation.created_at).toISOString() : null,
            created_at_formatted: reservation.created_at ? new Date(reservation.created_at).toLocaleString() : null,

            // Status
            reservation_status: reservation.reservation_status || 'Pending',
            payment_status: reservation.payment_status || 'Pending',

            // Financial
            total_amount: totalAmount.toFixed(2),
            amount_paid: amountPaid.toFixed(2),
            amount_due: amountDue.toFixed(2),
            payment_progress: paymentProgress,
            payment_count: reservation.payment_count || 0,
            payment_method: reservation.payment_method,
            last_payment_date: reservation.last_payment_date ? new Date(reservation.last_payment_date).toISOString() : null,
            last_payment_date_formatted: reservation.last_payment_date ? new Date(reservation.last_payment_date).toLocaleString() : null,
            mpesa_receipt: reservation.mpesa_receipt,

            // Guest details
            guest: {
                title: reservation.title || '',
                first_name: reservation.first_name || '',
                last_name: reservation.last_name || '',
                full_name: `${reservation.title || ''} ${reservation.first_name || ''} ${reservation.last_name || ''}`.trim(),
                email: reservation.email,
                nationality: reservation.nationality || '',
                passport_country: reservation.passport_country || '',
                phone_number: reservation.phone_number || '',
                national_id: reservation.national_id || '',
                passport_no: reservation.passport_no || ''
            },

            // Computed flags
            is_fully_paid: amountDue <= 0,
            is_overdue: amountDue > 0 && reservation.check_out && new Date(reservation.check_out) < new Date(),
            is_active: reservation.reservation_status === 'Permitted' ||
                (reservation.reservation_status === 'Pending' &&
                    reservation.created_at &&
                    (new Date() - new Date(reservation.created_at)) < 2 * 60 * 60 * 1000)
        };

        res.json({
            success: true,
            reservation: formattedReservation
        });

    } catch (err) {
        console.error('[Vercel] Single reservation error:', err);
        res.status(500).json({
            success: false,
            message: "Failed to fetch reservation details",
            error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});

app.put("/api/reservations/:id/status", (req, res) => {
    const reservationId = req.params.id;
    const { status } = req.body;
    if (!status) return res.status(400).json({ message: "Status is required" });

    db.query("UPDATE reservationsdetails SET status = ? WHERE reservation_id = ?", [status, reservationId],
        (err, result) => {
            if (err) {
                console.error("update reservation status error:", err);
                return res.status(500).json({ message: err.sqlMessage || "Server error" });
            }
            if (result.affectedRows === 0) return res.status(404).json({ message: "Reservation not found" });
            res.json({ message: "Status updated successfully" });
        });
});




// ============================================
// FIXED: Get Guest Details - VERCEL COMPATIBLE
// ============================================
app.get("/api/guestdetails", async (req, res) => {
    try {
        // VERCEL FIX: Add null check for req.session
        if (!req.session) {
            console.error("[Vercel] /api/guestdetails - Session is undefined");
            return res.status(500).json({
                success: false,
                message: "Session error",
                code: "SESSION_MISSING"
            });
        }

        // Check if user is logged in
        if (!req.session.user) {
            return res.status(401).json({
                success: false,
                message: "Not logged in",
                code: "NOT_LOGGED_IN"
            });
        }

        const email = req.session.user.email;

        // VERCEL FIX: Validate email
        if (!email) {
            console.error("[Vercel] /api/guestdetails - No email in session:", req.session.user);
            return res.status(400).json({
                success: false,
                message: "Invalid session data",
                code: "INVALID_SESSION"
            });
        }

        // Query guest details
        const [rows] = await db.promise().query(
            `SELECT 
                guest_id,
                email,
                title,
                first_name,
                last_name,
                nationality,
                passport_country,
                national_id,
                passport_no,
                phone_number,
                created_at,
                updated_at
            FROM guestdetails 
            WHERE email = ? 
            LIMIT 1`,
            [email]
        );

        if (!rows.length) {
            return res.status(404).json({
                success: false,
                message: "Guest details not found. Please complete your profile.",
                code: "GUEST_NOT_FOUND"
            });
        }

        const guest = rows[0];

        // VERCEL FIX: Format response with computed fields
        const formattedGuest = {
            ...guest,
            // Full name for easy display
            full_name: `${guest.title || ''} ${guest.first_name || ''} ${guest.last_name || ''}`.trim(),
            // Format dates
            created_at: guest.created_at ? new Date(guest.created_at).toISOString() : null,
            created_at_formatted: guest.created_at ? new Date(guest.created_at).toLocaleDateString() : null,
            updated_at: guest.updated_at ? new Date(guest.updated_at).toISOString() : null,
            updated_at_formatted: guest.updated_at ? new Date(guest.updated_at).toLocaleDateString() : null,
            // Boolean flags
            has_national_id: Boolean(guest.national_id),
            has_passport: Boolean(guest.passport_no),
            has_phone: Boolean(guest.phone_number),
            // Profile completion status
            profile_complete: Boolean(
                guest.first_name &&
                guest.last_name &&
                guest.nationality &&
                (guest.national_id || guest.passport_no) &&
                guest.phone_number
            )
        };

        // Log successful fetch (useful for debugging)
        console.log(`[Vercel] Guest details fetched for: ${email}`);

        res.json({
            success: true,
            guest: formattedGuest
        });

    } catch (error) {
        console.error("[Vercel] /api/guestdetails - Error:", error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch guest details",
            code: "SERVER_ERROR",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});




app.post("/api/payment/:reservationId/complete", async (req, res) => {
    const { reservationId } = req.params;
    const { phoneNumber, amount } = req.body;

    if (!phoneNumber || !amount) {
        return res.status(400).json({ message: "Phone number and amount are required." });
    }


    const phone = phoneNumber.startsWith("0") ? "254" + phoneNumber.slice(1) : phoneNumber;

    const time = new Date();
    const timestamp = time.toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
    const password = Buffer.from(MPESA_SHORTCODE + MPESA_PASSKEY + timestamp).toString("base64");

    try {

        const token = await getAccessToken();


        const mpesaRes = await axios.post(
            `${MPESA_BASE_URL}/mpesa/stkpush/v1/processrequest`,
            {
                BusinessShortCode: MPESA_SHORTCODE,
                Password: password,
                Timestamp: timestamp,
                TransactionType: "CustomerPayBillOnline",
                Amount: amount,
                PartyA: phone,
                PartyB: MPESA_SHORTCODE,
                PhoneNumber: phone,
                CallBackURL: process.env.MPESA_CALLBACK_URL,
                AccountReference: reservationId,
                TransactionDesc: "Hotel Booking"
            },
            { headers: { Authorization: `Bearer ${token}` } }
        );


        res.json({
            success: true,
            message: "STK Push initiated. Check your phone for the M-Pesa prompt.",
            mpesa: mpesaRes.data
        });
    } catch (err) {
        console.error("STK Push error:", err.response?.data || err.message);
        res.status(500).json({ message: "Failed to initiate STK Push.", error: err.response?.data || err.message });
    }
});


app.post("/api/payment/:reservationId/mpesa", async (req, res) => {
    const { reservationId } = req.params;
    const { amount, phone } = req.body;

    if (!reservationId || !amount || !phone) {
        return res.status(400).json({ success: false, message: "Missing required fields." });
    }

    try {

        const [reservationRows] = await db.promise().query(
            "SELECT guest_id FROM reservationsdetails WHERE reservation_id = ?",
            [reservationId]
        );

        if (!reservationRows.length) {
            return res.status(404).json({ success: false, message: "Reservation not found." });
        }

        const guestId = reservationRows[0].guest_id;


        const [existingPayments] = await db.promise().query(
            "SELECT payment_id, amount_paid FROM payments WHERE reservation_id = ? AND status = 'Pending'",
            [reservationId]
        );

        if (existingPayments.length === 0) {

            await db.promise().query(
                `INSERT INTO payments (reservation_id, guest_id, amount_paid, payment_method, status, payment_date)
                 VALUES (?, ?, 0.00, 'Mpesa', 'Pending', NOW())`,
                [reservationId, guestId]
            );
            console.log(`Created new payment record for reservation ${reservationId} with amount_paid = 0`);
        } else {
            console.log(`Using existing payment record for reservation ${reservationId}`);
        }

        const mpesaPhone = phone.startsWith("0") ? "254" + phone.substring(1) : phone;


        const time = new Date();
        const timestamp = time.toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
        const password = Buffer.from(MPESA_SHORTCODE + MPESA_PASSKEY + timestamp).toString("base64");

        const token = await getAccessToken();

        const mpesaRes = await axios.post(
            `${MPESA_BASE_URL}/mpesa/stkpush/v1/processrequest`,
            {
                BusinessShortCode: MPESA_SHORTCODE,
                Password: password,
                Timestamp: timestamp,
                TransactionType: "CustomerPayBillOnline",
                Amount: amount,
                PartyA: mpesaPhone,
                PartyB: MPESA_SHORTCODE,
                PhoneNumber: mpesaPhone,
                CallBackURL: process.env.MPESA_CALLBACK_URL,
                AccountReference: reservationId,
                TransactionDesc: "Hotel Booking"
            },
            { headers: { Authorization: `Bearer ${token}` } }
        );

        res.json({
            success: true,
            message: "STK Push initiated. Check your phone for the M-Pesa prompt.",
            mpesa: mpesaRes.data
        });

    } catch (err) {
        console.error("STK Push error:", err.response?.data || err.message);
        res.status(500).json({
            success: false,
            message: "Payment failed.",
            error: err.response?.data || err.message
        });
    }
});

app.patch("/api/reservations/:id/mark-paid", requireAdmin, async (req, res) => {
    const reservationId = req.params.id;
    const { paymentAmount, paymentMethod = 'Cash' } = req.body;

    if (!paymentAmount || isNaN(paymentAmount)) {
        return res.status(400).json({ message: "Valid payment amount is required" });
    }

    try {

        const [reservationRows] = await db.promise().query(
            "SELECT guest_id FROM reservationsdetails WHERE reservation_id = ?",
            [reservationId]
        );

        if (reservationRows.length === 0) {
            return res.status(404).json({ message: "Reservation not found" });
        }

        const guestId = reservationRows[0].guest_id;


        const [existingPayments] = await db.promise().query(
            "SELECT * FROM payments WHERE reservation_id = ? AND status = 'Paid'",
            [reservationId]
        );

        let paymentId;

        if (existingPayments.length > 0) {

            await db.promise().query(
                `UPDATE payments 
                 SET amount_paid = amount_paid + ?,
                     payment_date = NOW()
                 WHERE reservation_id = ? AND status = 'Paid'`,
                [paymentAmount, reservationId]
            );
            paymentId = existingPayments[0].payment_id;
        } else {

            const [paymentResult] = await db.promise().query(
                `INSERT INTO payments 
                 (reservation_id, guest_id, amount_paid, payment_method, status, payment_date)
                 VALUES (?, ?, ?, ?, 'Paid', NOW())`,
                [reservationId, guestId, paymentAmount, paymentMethod]
            );
            paymentId = paymentResult.insertId;
        }


        await db.promise().query(
            `UPDATE reservationsdetails 
             SET status = 'Permitted' 
             WHERE reservation_id = ? AND status = 'Pending'`,
            [reservationId]
        );

        res.json({
            message: "Payment marked as paid successfully",
            paymentId: paymentId,
            paymentAmount: paymentAmount,
            paymentMethod: paymentMethod
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});




async function getAccessToken() {
    const auth = Buffer.from(`${MPESA_CONSUMER_KEY}:${MPESA_CONSUMER_SECRET}`).toString("base64");
    const res = await axios.get(
        `${MPESA_BASE_URL}/oauth/v1/generate?grant_type=client_credentials`,
        { headers: { Authorization: `Basic ${auth}` } }
    );
    return res.data.access_token;
}



app.post("/pay/mpesa", async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Not logged in" });
    }

    const { reservationId, phoneNumber, amount } = req.body;
    const email = req.session.user.email;

    if (!reservationId || !phoneNumber || !amount) {
        return res.status(400).json({ success: false, message: "reservationId, phoneNumber, and amount are required" });
    }

    try {
        console.log("Initiating STK Push:", { reservationId, phoneNumber, amount, email });


        const [rows] = await db.promise().execute(
            `SELECT r.reservation_id
             FROM reservationsdetails r
             JOIN guestdetails gd ON r.guest_id = gd.guest_id
             JOIN guest g ON g.email = gd.email
             WHERE r.reservation_id = ? AND g.email = ?`,
            [reservationId, email]
        );

        if (rows.length === 0) {
            return res.status(403).json({ success: false, message: "You can only pay for your own reservations" });
        }


        const [guestRows] = await db.promise().query(
            "SELECT guest_id FROM guestdetails WHERE email = ? LIMIT 1",
            [email]
        );

        if (!guestRows.length) {
            return res.status(400).json({ success: false, message: "Guest not found" });
        }

        const guestId = guestRows[0].guest_id;


        const [existingPayments] = await db.promise().query(
            "SELECT payment_id FROM payments WHERE reservation_id = ? AND status = 'Pending'",
            [reservationId]
        );

        if (existingPayments.length === 0) {

            await db.promise().query(
                `INSERT INTO payments (reservation_id, guest_id, amount_paid, payment_method, status, payment_date)
                 VALUES (?, ?, 0.00, 'Mpesa', 'Pending', NOW())`,
                [reservationId, guestId]
            );
            console.log(`Created payment record for reservation ${reservationId}`);
        }


        const phone = phoneNumber.startsWith("0") ? "254" + phoneNumber.slice(1) : phoneNumber;


        const timestamp = new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
        const password = Buffer.from(MPESA_SHORTCODE + MPESA_PASSKEY + timestamp).toString("base64");


        const token = await getAccessToken();


        const mpesaResponse = await axios.post(
            `${MPESA_BASE_URL}/mpesa/stkpush/v1/processrequest`,
            {
                BusinessShortCode: MPESA_SHORTCODE,
                Password: password,
                Timestamp: timestamp,
                TransactionType: "CustomerPayBillOnline",
                Amount: amount,
                PartyA: phone,
                PartyB: MPESA_SHORTCODE,
                PhoneNumber: phone,
                CallBackURL: process.env.MPESA_CALLBACK_URL,
                AccountReference: reservationId,
                TransactionDesc: "Hotel Booking"
            },
            { headers: { Authorization: `Bearer ${token}` } }
        );

        console.log("STK Push raw response:", mpesaResponse.data);

        res.json({
            success: true,
            message: "STK Push initiated. Check your phone to complete the payment.",
            mpesaResponse: mpesaResponse.data
        });

    } catch (err) {
        console.error("STK Push error:", err.response?.data || err.message || err);
        res.status(500).json({
            success: false,
            message: "Payment initiation failed",
            error: err.response?.data || err.message
        });
    }
});

app.post("/mpesa/callback", async (req, res) => {
    try {
        const stkCallback = req.body?.Body?.stkCallback;
        if (!stkCallback) return res.json({ ResultCode: 0, ResultDesc: "No callback data" });

        const { ResultCode, ResultDesc, CallbackMetadata } = stkCallback;
        const accountRef = CallbackMetadata?.Item.find(i => i.Name === "AccountReference")?.Value;
        const amount = CallbackMetadata?.Item.find(i => i.Name === "Amount")?.Value;
        const mpesaReceipt = CallbackMetadata?.Item.find(i => i.Name === "MpesaReceiptNumber")?.Value;

        console.log("STK Callback received:", { ResultCode, ResultDesc, accountRef, amount, mpesaReceipt });

        if (ResultCode === 0 && accountRef) {

            const [reservationRows] = await db.promise().query(
                "SELECT guest_id FROM reservationsdetails WHERE reservation_id = ?",
                [accountRef]
            );

            if (reservationRows.length > 0) {
                const guestId = reservationRows[0].guest_id;


                const [existingPayments] = await db.promise().query(
                    "SELECT * FROM payments WHERE reservation_id = ?",
                    [accountRef]
                );

                if (existingPayments.length > 0) {

                    await db.promise().query(
                        `UPDATE payments 
                         SET amount_paid = amount_paid + ?, 
                             status = 'Paid', 
                             mpesa_receipt = ?,
                             payment_method = 'Mpesa',
                             payment_date = NOW()
                         WHERE reservation_id = ?`,
                        [amount, mpesaReceipt, accountRef]
                    );
                } else {

                    await db.promise().query(
                        `INSERT INTO payments 
                         (reservation_id, guest_id, amount_paid, payment_method, status, 
                          mpesa_receipt, payment_date)
                         VALUES (?, ?, ?, 'Mpesa', 'Paid', ?, NOW())`,
                        [accountRef, guestId, amount, mpesaReceipt]
                    );
                }


                await db.promise().query(
                    "UPDATE reservationsdetails SET status = 'Permitted' WHERE reservation_id = ?",
                    [accountRef]
                );

                console.log(`Payment confirmed for reservation ${accountRef}, amount: ${amount}, receipt: ${mpesaReceipt}`);
            }
        } else {
            console.warn("Payment failed or cancelled", stkCallback);


            await db.promise().query(
                "UPDATE payments SET status = 'Failed' WHERE reservation_id = ? AND status = 'Pending'",
                [accountRef]
            );
        }

        res.json({ ResultCode: 0, ResultDesc: "Success" });

    } catch (err) {
        console.error("Error processing M-Pesa callback:", err);
        res.status(500).json({ ResultCode: 1, ResultDesc: "Internal server error" });
    }
});


// ============================================
// FIXED: Get Payments with Pagination - VERCEL COMPATIBLE
// ============================================
app.get("/api/payments", requireAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 10, search = '', startDate, endDate } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);
        const pageSize = parseInt(limit);

        // VERCEL FIX: Build dynamic WHERE clause
        let whereConditions = ["p.status = 'Paid'"];
        let queryParams = [];
        let countParams = [];

        // Add search filter
        if (search) {
            whereConditions.push(`(
                gd.first_name LIKE ? OR 
                gd.last_name LIKE ? OR 
                gd.email LIKE ? OR 
                r.roomTag LIKE ? OR
                p.payment_method LIKE ? OR
                p.mpesa_receipt LIKE ?
            )`);
            const searchParam = `%${search}%`;
            queryParams.push(searchParam, searchParam, searchParam, searchParam, searchParam, searchParam);
            countParams.push(searchParam, searchParam, searchParam, searchParam, searchParam, searchParam);
        }

        // Add date range filter
        if (startDate && endDate) {
            whereConditions.push("DATE(p.payment_date) BETWEEN ? AND ?");
            queryParams.push(startDate, endDate);
            countParams.push(startDate, endDate);
        }

        const whereClause = "WHERE " + whereConditions.join(" AND ");

        // Main query with pagination
        const baseQuery = `
            SELECT 
                p.payment_id,
                p.reservation_id,
                p.amount_paid,
                p.payment_method,
                p.payment_date,
                p.status as payment_status,
                p.mpesa_receipt,
                p.created_at as payment_created_at,
                
                r.room_type,
                r.bedding_type,
                r.meal_plan,
                r.check_in,
                r.check_out,
                r.no_of_rooms,
                r.roomTag,
                r.nights,
                r.total_amount,
                r.status as reservation_status,
                
                gd.first_name,
                gd.last_name,
                gd.email,
                gd.phone_number,
                gd.nationality
                
            FROM payments p
            JOIN reservationsdetails r ON p.reservation_id = r.reservation_id
            JOIN guestdetails gd ON r.guest_id = gd.guest_id
            ${whereClause}
            ORDER BY p.payment_date DESC
            LIMIT ? OFFSET ?
        `;

        // Count query for pagination
        const countQuery = `
            SELECT COUNT(DISTINCT p.payment_id) as total
            FROM payments p
            JOIN reservationsdetails r ON p.reservation_id = r.reservation_id
            JOIN guestdetails gd ON r.guest_id = gd.guest_id
            ${whereClause}
        `;

        // Execute queries
        const queryParamsWithPagination = [...queryParams, pageSize, offset];
        const [payments] = await db.promise().query(baseQuery, queryParamsWithPagination);
        const [countResult] = await db.promise().query(countQuery, countParams);

        const total = countResult[0]?.total || 0;
        const totalPages = Math.ceil(total / pageSize);

        // VERCEL FIX: Format payments with proper number parsing
        const paymentsWithDetails = payments.map(payment => {
            const roomRent = parseNumericValue(payment.room_type);
            const bedRent = parseNumericValue(payment.bedding_type);
            const mealCost = parseNumericValue(payment.meal_plan);
            const nights = parseInt(payment.nights) || 1;
            const rooms = parseInt(payment.no_of_rooms) || 1;

            // Calculate breakdown
            const roomTotal = roomRent * rooms * nights;
            const bedTotal = bedRent * rooms * nights;
            const mealTotal = mealCost * rooms * nights;
            const subtotal = parseFloat(payment.total_amount || 0);
            const amountPaid = parseFloat(payment.amount_paid || 0);

            return {
                // Payment details
                payment_id: payment.payment_id,
                reservation_id: payment.reservation_id,
                amount_paid: amountPaid.toFixed(2),
                payment_method: payment.payment_method || 'Mpesa',
                payment_date: payment.payment_date ? new Date(payment.payment_date).toISOString() : null,
                payment_date_formatted: payment.payment_date ? new Date(payment.payment_date).toLocaleString() : null,
                mpesa_receipt: payment.mpesa_receipt || 'N/A',
                payment_status: payment.payment_status,

                // Guest info
                guest_name: `${payment.first_name || ''} ${payment.last_name || ''}`.trim() || 'N/A',
                guest_email: payment.email,
                guest_phone: payment.phone_number,
                guest_nationality: payment.nationality,

                // Booking details
                room_type: payment.room_type,
                bedding_type: payment.bedding_type,
                meal_plan: payment.meal_plan,
                room_tag: payment.roomTag,
                check_in: payment.check_in ? new Date(payment.check_in).toISOString().split('T')[0] : null,
                check_out: payment.check_out ? new Date(payment.check_out).toISOString().split('T')[0] : null,
                nights: nights,
                rooms: rooms,

                // Financial breakdown
                room_rent_per_night: roomRent.toFixed(2),
                bed_rent_per_night: bedRent.toFixed(2),
                meal_cost_per_night: mealCost.toFixed(2),
                room_total: roomTotal.toFixed(2),
                bed_total: bedTotal.toFixed(2),
                meal_total: mealTotal.toFixed(2),
                subtotal: subtotal.toFixed(2),
                gr_total: amountPaid.toFixed(2),

                // Reservation status
                reservation_status: payment.reservation_status,

                // Timestamps
                created_at: payment.payment_created_at ? new Date(payment.payment_created_at).toISOString() : null
            };
        });

        // VERCEL FIX: Add payment summary statistics
        const totalAmount = paymentsWithDetails.reduce((sum, p) => sum + parseFloat(p.amount_paid), 0);
        const paymentMethods = paymentsWithDetails.reduce((acc, p) => {
            acc[p.payment_method] = (acc[p.payment_method] || 0) + 1;
            return acc;
        }, {});

        res.json({
            success: true,
            payments: paymentsWithDetails,
            pagination: {
                page: parseInt(page),
                limit: pageSize,
                total,
                totalPages,
                hasNext: parseInt(page) < totalPages,
                hasPrev: parseInt(page) > 1
            },
            summary: {
                total_amount: totalAmount.toFixed(2),
                payment_methods: paymentMethods,
                count: paymentsWithDetails.length
            },
            filters: {
                search: search || null,
                startDate: startDate || null,
                endDate: endDate || null
            }
        });

    } catch (error) {
        console.error('[Vercel] Error fetching payments:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch payment records',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// FIXED: Get Payment Receipt - VERCEL COMPATIBLE
// ============================================
app.get("/api/payment/receipt/:reservationId", requireAdmin, async (req, res) => {
    try {
        const { reservationId } = req.params;

        // VERCEL FIX: Validate reservation ID
        if (!reservationId || isNaN(parseInt(reservationId))) {
            return res.status(400).json({
                success: false,
                message: 'Invalid reservation ID'
            });
        }

        // VERCEL FIX: Enhanced receipt query with more details
        const query = `
            SELECT 
                r.reservation_id,
                r.created_at as booking_date,
                
                -- Guest details
                gd.title,
                gd.first_name,
                gd.last_name,
                gd.email,
                gd.phone_number,
                gd.national_id,
                gd.passport_no,
                gd.nationality,
                gd.passport_country,
                
                -- Booking details
                r.room_type,
                r.bedding_type,
                r.check_in,
                r.check_out,
                r.no_of_rooms,
                r.meal_plan,
                r.roomTag,
                r.nights,
                r.total_amount,
                r.status as reservation_status,
                
                -- Payment details
                p.payment_id,
                p.amount_paid,
                p.payment_method,
                p.payment_date,
                p.status as payment_status,
                p.mpesa_receipt,
                p.created_at as payment_created_at
                
            FROM reservationsdetails r
            JOIN guestdetails gd ON r.guest_id = gd.guest_id
            JOIN payments p ON r.reservation_id = p.reservation_id
            WHERE r.reservation_id = ? AND p.status = 'Paid'
            ORDER BY p.payment_date DESC
            LIMIT 1
        `;

        const [results] = await db.promise().query(query, [reservationId]);

        if (results.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Payment receipt not found',
                code: 'RECEIPT_NOT_FOUND'
            });
        }

        const payment = results[0];

        // Parse numeric values
        const roomRent = parseNumericValue(payment.room_type);
        const bedRent = parseNumericValue(payment.bedding_type);
        const mealCost = parseNumericValue(payment.meal_plan);
        const nights = parseInt(payment.nights) || 1;
        const rooms = parseInt(payment.no_of_rooms) || 1;

        // Calculate totals
        const roomTotal = roomRent * rooms * nights;
        const bedTotal = bedRent * rooms * nights;
        const mealTotal = mealCost * rooms * nights;
        const subtotal = parseFloat(payment.total_amount || 0);
        const amountPaid = parseFloat(payment.amount_paid || 0);
        const taxRate = 0.16; // 16% VAT
        const taxAmount = subtotal * taxRate;
        const grandTotal = subtotal + taxAmount;

        // VERCEL FIX: Generate unique receipt number
        const receiptNumber = `RCP-${payment.reservation_id}-${new Date().getFullYear()}${String(new Date().getMonth() + 1).padStart(2, '0')}${String(payment.payment_id).padStart(6, '0')}`;

        const receipt = {
            // Receipt metadata
            receipt_number: receiptNumber,
            receipt_date: new Date().toISOString(),
            receipt_date_formatted: formatDateForReceipt(new Date()),

            // Hotel information
            hotel: {
                name: "THE JACKS' HOTEL",
                address: "123 Hotel Street, Nairobi, Kenya",
                phone: "+254 700 000 000",
                email: "info@thejacks.com",
                website: "www.thejacks.com",
                vat_reg: "P051-1234-5678"
            },

            // Guest information
            guest: {
                name: `${payment.title || ''} ${payment.first_name} ${payment.last_name}`.trim(),
                email: payment.email,
                phone: payment.phone_number,
                nationality: payment.nationality,
                id_type: payment.national_id ? 'National ID' : 'Passport',
                id_number: payment.national_id || payment.passport_no || 'N/A',
                id_country: payment.passport_country || 'Kenya'
            },

            // Booking information
            booking: {
                reservation_id: payment.reservation_id,
                booking_date: payment.booking_date ? formatDateForReceipt(payment.booking_date) : 'N/A',
                check_in: formatDateForReceipt(payment.check_in),
                check_out: formatDateForReceipt(payment.check_out),
                nights: nights,
                rooms: rooms,
                room_tag: payment.roomTag || 'Not assigned',
                room_type: getRoomTypeDescription(payment.room_type),
                bed_type: getBedTypeDescription(payment.bedding_type),
                meal_plan: getMealPlanDescription(payment.meal_plan),
                status: payment.reservation_status
            },

            // Pricing breakdown
            pricing: {
                items: [
                    {
                        description: `Room (${getRoomTypeLabel(payment.room_type)})`,
                        quantity: rooms,
                        nights: nights,
                        rate: roomRent,
                        amount: roomTotal
                    },
                    {
                        description: `Bed (${getBedTypeLabel(payment.bedding_type)})`,
                        quantity: rooms,
                        nights: nights,
                        rate: bedRent,
                        amount: bedTotal
                    },
                    {
                        description: `Meal Plan (${getMealPlanLabel(payment.meal_plan)})`,
                        quantity: rooms,
                        nights: nights,
                        rate: mealCost,
                        amount: mealTotal
                    }
                ].filter(item => item.amount > 0),

                subtotal: subtotal,
                tax_rate: "16%",
                tax_amount: taxAmount,
                grand_total: grandTotal,

                // Formatted for display
                subtotal_formatted: subtotal.toFixed(2),
                tax_amount_formatted: taxAmount.toFixed(2),
                grand_total_formatted: grandTotal.toFixed(2)
            },

            // Payment information
            payment: {
                payment_id: payment.payment_id,
                amount_paid: amountPaid,
                amount_paid_formatted: amountPaid.toFixed(2),
                payment_method: payment.payment_method || 'Mpesa',
                payment_date: formatDateForReceipt(payment.payment_date),
                payment_time: payment.payment_date ? new Date(payment.payment_date).toLocaleTimeString() : 'N/A',
                transaction_id: payment.mpesa_receipt || `TXN-${payment.payment_id}`,
                payment_status: payment.payment_status,
                balance_due: (grandTotal - amountPaid).toFixed(2),
                is_fully_paid: amountPaid >= grandTotal
            },

            // Footer
            footer: {
                thank_you: "Thank you for choosing THE JACKS' HOTEL!",
                policy: "This is an electronically generated receipt. Valid without signature.",
                generated_by: req.session.admin?.adminId || 'Admin',
                generated_at: new Date().toISOString()
            }
        };

        res.json({
            success: true,
            receipt,
            meta: {
                version: "1.0",
                timestamp: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('[Vercel] Error generating receipt:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to generate receipt',
            code: 'RECEIPT_GENERATION_FAILED',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// FIXED: Get Payment Statistics - VERCEL COMPATIBLE
// ============================================
app.get("/api/payment-statistics", requireAdmin, async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];
        const thisMonth = new Date().getMonth() + 1;
        const thisYear = new Date().getFullYear();
        const startOfWeek = new Date();
        startOfWeek.setDate(startOfWeek.getDate() - 7);
        const startOfMonth = new Date();
        startOfMonth.setDate(1);
        const startOfYear = new Date();
        startOfYear.setMonth(0, 1);

        // VERCEL FIX: Execute all queries in parallel with better error handling
        const [
            todayStats,
            weekStats,
            monthStats,
            yearStats,
            overallStats,
            methodStats,
            dailyStats,
            topPayments
        ] = await Promise.all([
            // Today's payments
            db.promise().query(
                `SELECT 
                    COUNT(*) as count,
                    COALESCE(SUM(amount_paid), 0) as total
                 FROM payments 
                 WHERE DATE(payment_date) = CURDATE() AND status = 'Paid'`
            ),

            // This week's payments
            db.promise().query(
                `SELECT 
                    COUNT(*) as count,
                    COALESCE(SUM(amount_paid), 0) as total
                 FROM payments 
                 WHERE payment_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) 
                 AND status = 'Paid'`
            ),

            // This month's payments
            db.promise().query(
                `SELECT 
                    COUNT(*) as count,
                    COALESCE(SUM(amount_paid), 0) as total
                 FROM payments 
                 WHERE MONTH(payment_date) = ? AND YEAR(payment_date) = ? 
                 AND status = 'Paid'`,
                [thisMonth, thisYear]
            ),

            // This year's payments
            db.promise().query(
                `SELECT 
                    COUNT(*) as count,
                    COALESCE(SUM(amount_paid), 0) as total
                 FROM payments 
                 WHERE YEAR(payment_date) = ? AND status = 'Paid'`,
                [thisYear]
            ),

            // Overall statistics
            db.promise().query(
                `SELECT 
                    COUNT(*) as total_count,
                    COALESCE(SUM(amount_paid), 0) as overall_total,
                    AVG(amount_paid) as average_payment,
                    MIN(amount_paid) as min_payment,
                    MAX(amount_paid) as max_payment,
                    COUNT(DISTINCT reservation_id) as unique_reservations,
                    COUNT(DISTINCT guest_id) as unique_guests
                 FROM payments 
                 WHERE status = 'Paid'`
            ),

            // Payment method breakdown
            db.promise().query(
                `SELECT 
                    COALESCE(payment_method, 'Unknown') as payment_method,
                    COUNT(*) as count,
                    COALESCE(SUM(amount_paid), 0) as total,
                    AVG(amount_paid) as average,
                    COUNT(DISTINCT reservation_id) as reservations
                 FROM payments 
                 WHERE status = 'Paid'
                 GROUP BY payment_method
                 ORDER BY total DESC`
            ),

            // Daily statistics for last 30 days
            db.promise().query(
                `SELECT 
                    DATE(payment_date) as date,
                    DAYNAME(payment_date) as day_name,
                    COUNT(*) as count,
                    COALESCE(SUM(amount_paid), 0) as total,
                    AVG(amount_paid) as average
                 FROM payments 
                 WHERE payment_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY) 
                 AND status = 'Paid'
                 GROUP BY DATE(payment_date), DAYNAME(payment_date)
                 ORDER BY date DESC`
            ),

            // Top 5 largest payments
            db.promise().query(
                `SELECT 
                    p.payment_id,
                    p.amount_paid,
                    p.payment_method,
                    p.payment_date,
                    CONCAT(gd.first_name, ' ', gd.last_name) as guest_name,
                    r.reservation_id
                 FROM payments p
                 JOIN reservationsdetails r ON p.reservation_id = r.reservation_id
                 JOIN guestdetails gd ON r.guest_id = gd.guest_id
                 WHERE p.status = 'Paid'
                 ORDER BY p.amount_paid DESC
                 LIMIT 5`
            )
        ]);

        // VERCEL FIX: Process and format statistics
        const statistics = {
            periods: {
                today: {
                    count: todayStats[0][0]?.count || 0,
                    total: parseFloat(todayStats[0][0]?.total || 0).toFixed(2)
                },
                this_week: {
                    count: weekStats[0][0]?.count || 0,
                    total: parseFloat(weekStats[0][0]?.total || 0).toFixed(2)
                },
                this_month: {
                    count: monthStats[0][0]?.count || 0,
                    total: parseFloat(monthStats[0][0]?.total || 0).toFixed(2)
                },
                this_year: {
                    count: yearStats[0][0]?.count || 0,
                    total: parseFloat(yearStats[0][0]?.total || 0).toFixed(2)
                },
                overall: {
                    count: overallStats[0][0]?.total_count || 0,
                    total: parseFloat(overallStats[0][0]?.overall_total || 0).toFixed(2),
                    average: parseFloat(overallStats[0][0]?.average_payment || 0).toFixed(2),
                    min_payment: parseFloat(overallStats[0][0]?.min_payment || 0).toFixed(2),
                    max_payment: parseFloat(overallStats[0][0]?.max_payment || 0).toFixed(2),
                    unique_reservations: overallStats[0][0]?.unique_reservations || 0,
                    unique_guests: overallStats[0][0]?.unique_guests || 0
                }
            },

            payment_methods: methodStats[0].map(method => ({
                method: method.payment_method,
                count: method.count,
                total: parseFloat(method.total).toFixed(2),
                average: parseFloat(method.average || 0).toFixed(2),
                reservations: method.reservations,
                percentage: overallStats[0][0]?.overall_total > 0
                    ? ((method.total / overallStats[0][0].overall_total) * 100).toFixed(1)
                    : 0
            })),

            daily: dailyStats[0].map(day => ({
                date: day.date,
                day_name: day.day_name,
                count: day.count,
                total: parseFloat(day.total).toFixed(2),
                average: parseFloat(day.average || 0).toFixed(2)
            })),

            top_payments: topPayments[0].map(payment => ({
                payment_id: payment.payment_id,
                reservation_id: payment.reservation_id,
                amount: parseFloat(payment.amount_paid).toFixed(2),
                method: payment.payment_method,
                date: new Date(payment.payment_date).toISOString(),
                guest_name: payment.guest_name
            })),

            summary: {
                total_revenue: parseFloat(overallStats[0][0]?.overall_total || 0).toFixed(2),
                total_transactions: overallStats[0][0]?.total_count || 0,
                average_transaction: parseFloat(overallStats[0][0]?.average_payment || 0).toFixed(2),
                successful_rate: "100%", // Since we only query Paid status
                currency: "KES"
            }
        };

        res.json({
            success: true,
            statistics,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('[Vercel] Error fetching payment statistics:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch payment statistics',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// FIXED: Export Payments to CSV - VERCEL COMPATIBLE
// ============================================
app.get("/api/payments/export", requireAdmin, async (req, res) => {
    try {
        const { startDate, endDate, format = 'csv' } = req.query;

        // VERCEL FIX: Enhanced export query with more fields
        let query = `
            SELECT 
                p.payment_id,
                p.reservation_id,
                p.amount_paid,
                p.payment_method,
                p.payment_date,
                p.status,
                p.mpesa_receipt,
                p.created_at as payment_created_at,
                
                CONCAT(gd.first_name, ' ', gd.last_name) as guest_name,
                gd.email as guest_email,
                gd.phone_number as guest_phone,
                gd.nationality as guest_nationality,
                gd.national_id,
                gd.passport_no,
                
                r.roomTag,
                r.room_type,
                r.bedding_type,
                r.meal_plan,
                r.check_in,
                r.check_out,
                r.nights,
                r.no_of_rooms,
                r.total_amount as booking_total,
                r.status as reservation_status,
                r.created_at as booking_date
                
            FROM payments p
            JOIN reservationsdetails r ON p.reservation_id = r.reservation_id
            JOIN guestdetails gd ON r.guest_id = gd.guest_id
            WHERE p.status = 'Paid'
        `;

        const params = [];

        if (startDate && endDate) {
            query += ` AND DATE(p.payment_date) BETWEEN ? AND ?`;
            params.push(startDate, endDate);
        }

        query += ` ORDER BY p.payment_date DESC`;

        const [payments] = await db.promise().query(query, params);

        if (payments.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'No payment data found for export'
            });
        }

        // VERCEL FIX: Enhanced CSV headers with better organization
        const csvHeaders = [
            // Payment Information
            'Payment ID', 'Reservation ID', 'Transaction ID', 'Amount (KES)',
            'Payment Method', 'Payment Date', 'Payment Time', 'Payment Status',

            // Guest Information
            'Guest Name', 'Guest Email', 'Guest Phone', 'Nationality',
            'ID Type', 'ID Number',

            // Booking Information
            'Room Tag(s)', 'Room Type', 'Bed Type', 'Meal Plan',
            'Check In Date', 'Check Out Date', 'Nights', 'Number of Rooms',
            'Booking Total (KES)', 'Booking Status', 'Booking Date',

            // Additional
            'Created At'
        ];

        const csvRows = payments.map(p => {
            const paymentDate = p.payment_date ? new Date(p.payment_date) : null;
            const checkIn = p.check_in ? new Date(p.check_in) : null;
            const checkOut = p.check_out ? new Date(p.check_out) : null;

            return [
                // Payment Information
                p.payment_id,
                p.reservation_id,
                p.mpesa_receipt || `PAY-${p.payment_id}`,
                parseFloat(p.amount_paid || 0).toFixed(2),
                p.payment_method || 'Mpesa',
                paymentDate ? paymentDate.toISOString().split('T')[0] : 'N/A',
                paymentDate ? paymentDate.toLocaleTimeString() : 'N/A',
                p.status,

                // Guest Information
                `"${p.guest_name || 'N/A'}"`,
                p.guest_email || 'N/A',
                p.guest_phone || 'N/A',
                p.guest_nationality || 'N/A',
                p.national_id ? 'National ID' : (p.passport_no ? 'Passport' : 'N/A'),
                p.national_id || p.passport_no || 'N/A',

                // Booking Information
                `"${p.roomTag || 'N/A'}"`,
                p.room_type || 'N/A',
                p.bedding_type || 'N/A',
                p.meal_plan || 'N/A',
                checkIn ? checkIn.toISOString().split('T')[0] : 'N/A',
                checkOut ? checkOut.toISOString().split('T')[0] : 'N/A',
                p.nights || 1,
                p.no_of_rooms || 1,
                parseFloat(p.booking_total || 0).toFixed(2),
                p.reservation_status || 'N/A',
                p.booking_date ? new Date(p.booking_date).toISOString().split('T')[0] : 'N/A',

                // Additional
                p.payment_created_at ? new Date(p.payment_created_at).toISOString() : 'N/A'
            ];
        });

        // Generate filename with date range
        const dateStr = startDate && endDate
            ? `${startDate}_to_${endDate}`
            : new Date().toISOString().split('T')[0];

        const filename = `payments_export_${dateStr}.csv`;

        // Create CSV content
        const csvContent = [
            csvHeaders.join(','),
            ...csvRows.map(row => row.join(','))
        ].join('\n');

        // VERCEL FIX: Set proper headers for file download
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Length', Buffer.byteLength(csvContent, 'utf8'));
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');

        res.send(csvContent);

    } catch (error) {
        console.error('[Vercel] Error exporting payments:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to export payment data',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// HELPER FUNCTIONS - VERCEL COMPATIBLE
// ============================================

function parseNumericValue(value) {
    if (!value) return 0;
    if (!isNaN(value) && !isNaN(parseFloat(value))) {
        return parseFloat(value);
    }
    const numericMatch = String(value).match(/(\d+(\.\d+)?)/);
    return numericMatch ? parseFloat(numericMatch[1]) : 0;
}

function formatDateForReceipt(dateString) {
    if (!dateString) return 'N/A';
    try {
        const date = new Date(dateString);
        if (isNaN(date.getTime())) return dateString;
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    } catch (e) {
        return dateString;
    }
}

function getRoomTypeDescription(value) {
    const descriptions = {
        '5000': 'Standard Room - Queen bed, AC, TV, Workspace',
        '7500': 'Deluxe Room - King bed, AC, TV, Mini-bar, City view',
        '12000': 'Suite - King bed, Living area, Jacuzzi, Garden view',
        '18000': 'Family Suite - Two bedrooms, Kitchenette, Balcony, Pool view'
    };
    return descriptions[value] || `Room Type (${value})`;
}

function getBedTypeDescription(value) {
    const descriptions = {
        '0': 'No bed option selected',
        '100': 'Single Bed - 90x190cm',
        '150': 'Double Bed - 140x190cm',
        '200': 'King Size Bed - 180x200cm',
        '250': 'Twin Beds - 2x Single beds'
    };
    return descriptions[value] || `Bed Type (${value})`;
}

function getMealPlanDescription(value) {
    const descriptions = {
        '0': 'No meals included',
        '500': 'Breakfast Only - Continental breakfast buffet',
        '1200': 'Half Board - Breakfast & Dinner',
        '2000': 'Full Board - Breakfast, Lunch & Dinner'
    };
    return descriptions[value] || `Meal Plan (${value})`;
}

function getRoomTypeLabel(value) {
    const labels = {
        '5000': 'Standard Room',
        '7500': 'Deluxe Room',
        '12000': 'Suite',
        '18000': 'Family Suite'
    };
    return labels[value] || `Room ${value}`;
}

function getBedTypeLabel(value) {
    const labels = {
        '0': 'None',
        '100': 'Single',
        '150': 'Double',
        '200': 'King',
        '250': 'Twin'
    };
    return labels[value] || `Bed ${value}`;
}

function getMealPlanLabel(value) {
    const labels = {
        '0': 'None',
        '500': 'Breakfast',
        '1200': 'Half Board',
        '2000': 'Full Board'
    };
    return labels[value] || `Meal ${value}`;
}


app.delete("/api/payments/:paymentId", requireAdmin, async (req, res) => {
    try {
        const { paymentId } = req.params;

        const [result] = await db.promise().query(
            'DELETE FROM payments WHERE payment_id = ?',
            [paymentId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Payment record not found'
            });
        }

        res.json({
            success: true,
            message: 'Payment record deleted successfully'
        });

    } catch (error) {
        console.error('Error deleting payment:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete payment record'
        });
    }
});

// ============================================
// FIXED: Payment Receipt - VERCEL COMPATIBLE
// ============================================
app.get("/api/payment/receipt/:reservationId", requireAdmin, async (req, res) => {
    try {
        const { reservationId } = req.params;

        // VERCEL FIX: Validate reservation ID
        if (!reservationId || isNaN(parseInt(reservationId))) {
            return res.status(400).json({
                success: false,
                message: 'Invalid reservation ID',
                code: 'INVALID_ID'
            });
        }

        const query = `
            SELECT 
                r.reservation_id,
                r.created_at as booking_date,
                
                -- Guest details
                gd.title,
                gd.first_name,
                gd.last_name,
                gd.email,
                gd.phone_number,
                gd.national_id,
                gd.passport_no,
                gd.nationality,
                gd.passport_country,
                
                -- Booking details
                r.room_type,
                r.bedding_type,
                r.check_in,
                r.check_out,
                r.no_of_rooms,
                r.meal_plan,
                r.roomTag,
                r.nights,
                r.total_amount,
                r.status as reservation_status,
                
                -- Payment details
                p.payment_id,
                p.amount_paid,
                p.payment_method,
                p.payment_date,
                p.mpesa_receipt,
                p.status as payment_status,
                p.created_at as payment_created_at
                
            FROM reservationsdetails r
            JOIN guestdetails gd ON r.guest_id = gd.guest_id
            JOIN payments p ON r.reservation_id = p.reservation_id
            WHERE r.reservation_id = ? AND p.status = 'Paid'
            ORDER BY p.payment_date DESC
            LIMIT 1
        `;

        const [results] = await db.promise().query(query, [reservationId]);

        if (results.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Payment receipt not found',
                code: 'RECEIPT_NOT_FOUND'
            });
        }

        const payment = results[0];

        // VERCEL FIX: Parse numeric values safely
        const roomRent = parseFloat(payment.room_type) || 0;
        const bedRent = parseFloat(payment.bedding_type) || 0;
        const mealCost = parseFloat(payment.meal_plan) || 0;
        const nights = parseInt(payment.nights) || 1;
        const rooms = parseInt(payment.no_of_rooms) || 1;
        const totalAmount = parseFloat(payment.total_amount) || 0;
        const amountPaid = parseFloat(payment.amount_paid) || 0;

        // VERCEL FIX: Calculate totals
        const totalRoomRent = roomRent * rooms * nights;
        const totalBedRent = bedRent * rooms * nights;
        const totalMeals = mealCost * rooms * nights;
        const calculatedTotal = totalRoomRent + totalBedRent + totalMeals;

        // VERCEL FIX: Generate unique receipt number
        const receiptNumber = `RCP-${payment.reservation_id}-${new Date().getFullYear()}${String(new Date().getMonth() + 1).padStart(2, '0')}`;

        const receipt = {
            // Receipt metadata
            receipt_number: receiptNumber,
            receipt_date: new Date().toISOString(),
            receipt_date_formatted: new Date().toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'long',
                day: 'numeric'
            }),

            // Reservation info
            reservation_id: payment.reservation_id,
            booking_date: payment.booking_date ? new Date(payment.booking_date).toLocaleDateString() : 'N/A',

            // Guest information
            guest: {
                name: `${payment.title || ''} ${payment.first_name || ''} ${payment.last_name || ''}`.trim() || 'N/A',
                email: payment.email || 'N/A',
                phone: payment.phone_number || 'N/A',
                nationality: payment.nationality || 'N/A',
                id_type: payment.national_id ? 'National ID' : (payment.passport_no ? 'Passport' : 'N/A'),
                id_number: payment.national_id || payment.passport_no || 'N/A',
                id_country: payment.passport_country || 'Kenya'
            },

            // Booking information
            booking: {
                check_in: payment.check_in ? new Date(payment.check_in).toLocaleDateString() : 'N/A',
                check_out: payment.check_out ? new Date(payment.check_out).toLocaleDateString() : 'N/A',
                nights: nights,
                rooms: rooms,
                room_tag: payment.roomTag || 'Not assigned',
                room_type: getRoomTypeLabel(payment.room_type),
                bed_type: getBedTypeLabel(payment.bedding_type),
                meal_plan: getMealPlanLabel(payment.meal_plan),
                status: payment.reservation_status || 'N/A'
            },

            // Pricing breakdown
            pricing: {
                per_night: {
                    room: roomRent.toFixed(2),
                    bed: bedRent.toFixed(2),
                    meal: mealCost.toFixed(2)
                },
                totals: {
                    room: totalRoomRent.toFixed(2),
                    bed: totalBedRent.toFixed(2),
                    meals: totalMeals.toFixed(2),
                    subtotal: totalAmount.toFixed(2),
                    calculated_total: calculatedTotal.toFixed(2)
                }
            },

            // Payment information
            payment: {
                payment_id: payment.payment_id,
                amount_paid: amountPaid.toFixed(2),
                payment_method: payment.payment_method || 'Mpesa',
                payment_date: payment.payment_date ? new Date(payment.payment_date).toLocaleString() : 'N/A',
                transaction_id: payment.mpesa_receipt || `TXN-${payment.payment_id}`,
                payment_status: payment.payment_status,
                balance_due: (totalAmount - amountPaid).toFixed(2),
                is_fully_paid: amountPaid >= totalAmount
            },

            // Hotel information
            hotel: {
                name: "THE JACKS' HOTEL",
                address: "123 Hotel Street, Nairobi, Kenya",
                phone: "+254 700 000 000",
                email: "info@thejacks.com",
                website: "www.thejacks.com"
            }
        };

        res.json({
            success: true,
            receipt,
            meta: {
                generated_at: new Date().toISOString(),
                generated_by: req.session.admin?.adminId || 'Admin'
            }
        });

    } catch (error) {
        console.error('[Vercel] Error generating receipt:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to generate receipt',
            code: 'RECEIPT_GENERATION_FAILED',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// FIXED: Notifications Count - VERCEL COMPATIBLE
// ============================================
app.get("/api/notifications/count", requireLogin, async (req, res) => {
    try {
        // VERCEL FIX: Add session validation
        if (!req.session || !req.session.user) {
            return res.status(401).json({
                success: false,
                message: "Not logged in",
                code: "UNAUTHORIZED"
            });
        }

        const email = req.session.user.email;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Invalid session data",
                code: "INVALID_SESSION"
            });
        }

        // VERCEL FIX: Check if notifications table exists, if not return 0
        try {
            const [rows] = await db.promise().query(
                `SELECT COUNT(*) as count FROM notifications 
                 WHERE email = ? AND is_read = 0`,
                [email]
            );

            const count = rows[0]?.count || 0;

            res.json({
                success: true,
                count: count,
                has_notifications: count > 0
            });
        } catch (dbError) {
            // VERCEL FIX: If table doesn't exist, return 0 gracefully
            if (dbError.code === 'ER_NO_SUCH_TABLE') {
                console.log('[Vercel] Notifications table does not exist');
                return res.json({
                    success: true,
                    count: 0,
                    has_notifications: false,
                    table_exists: false
                });
            }
            throw dbError;
        }

    } catch (error) {
        console.error('[Vercel] Error fetching notification count:', error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch notification count",
            code: "SERVER_ERROR",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// FIXED: Payment Summary - VERCEL COMPATIBLE
// ============================================
app.get("/api/payment-summary", requireAdmin, async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];
        const thisMonth = new Date().getMonth() + 1;
        const thisYear = new Date().getFullYear();

        // VERCEL FIX: Execute queries in parallel with error handling for each
        const [
            todayResult,
            monthResult,
            paidResult,
            pendingResult,
            uniqueGuestsResult,
            averageResult
        ] = await Promise.all([
            // Today's total
            db.promise().query(
                `SELECT COALESCE(SUM(amount_paid), 0) as today_total,
                        COUNT(*) as today_count
                 FROM payments 
                 WHERE DATE(payment_date) = CURDATE() AND status = 'Paid'`
            ),

            // This month's total
            db.promise().query(
                `SELECT COALESCE(SUM(amount_paid), 0) as month_total,
                        COUNT(*) as month_count
                 FROM payments 
                 WHERE MONTH(payment_date) = ? AND YEAR(payment_date) = ? 
                 AND status = 'Paid'`,
                [thisMonth, thisYear]
            ),

            // Total paid transactions
            db.promise().query(
                `SELECT COUNT(*) as total_count, 
                        COALESCE(SUM(amount_paid), 0) as lifetime_total
                 FROM payments 
                 WHERE status = 'Paid'`
            ),

            // Pending payments
            db.promise().query(
                `SELECT COUNT(*) as pending_count,
                        COALESCE(SUM(amount_paid), 0) as pending_amount
                 FROM payments 
                 WHERE status = 'Pending'`
            ),

            // Unique paying guests
            db.promise().query(
                `SELECT COUNT(DISTINCT guest_id) as unique_guests
                 FROM payments 
                 WHERE status = 'Paid'`
            ),

            // Average payment amount
            db.promise().query(
                `SELECT COALESCE(AVG(amount_paid), 0) as average_payment
                 FROM payments 
                 WHERE status = 'Paid'`
            )
        ]);

        res.json({
            success: true,
            summary: {
                today: {
                    total: parseFloat(todayResult[0][0].today_total || 0).toFixed(2),
                    count: parseInt(todayResult[0][0].today_count || 0)
                },
                this_month: {
                    total: parseFloat(monthResult[0][0].month_total || 0).toFixed(2),
                    count: parseInt(monthResult[0][0].month_count || 0)
                },
                lifetime: {
                    total: parseFloat(paidResult[0][0].lifetime_total || 0).toFixed(2),
                    count: parseInt(paidResult[0][0].total_count || 0),
                    unique_guests: parseInt(uniqueGuestsResult[0][0].unique_guests || 0),
                    average: parseFloat(averageResult[0][0].average_payment || 0).toFixed(2)
                },
                pending: {
                    count: parseInt(pendingResult[0][0].pending_count || 0),
                    amount: parseFloat(pendingResult[0][0].pending_amount || 0).toFixed(2)
                }
            },
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('[Vercel] Error fetching payment summary:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch payment summary',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// FIXED: Profit Statistics - VERCEL COMPATIBLE
// ============================================
app.get("/api/profit-statistics", requireAdmin, async (req, res) => {
    try {
        // VERCEL FIX: Get last 7 days with proper date handling
        const query = `
            WITH RECURSIVE dates AS (
                SELECT CURDATE() - INTERVAL 6 DAY as date
                UNION ALL
                SELECT date + INTERVAL 1 DAY
                FROM dates
                WHERE date < CURDATE()
            )
            SELECT 
                dates.date,
                COALESCE(SUM(p.amount_paid), 0) as profit,
                COALESCE(COUNT(p.payment_id), 0) as transaction_count
            FROM dates
            LEFT JOIN payments p ON DATE(p.payment_date) = dates.date AND p.status = 'Paid'
            GROUP BY dates.date
            ORDER BY dates.date ASC
        `;

        const [profitData] = await db.promise().query(query);

        // VERCEL FIX: Format for chart display
        const chartData = profitData.map(day => ({
            date: day.date.toISOString().split('T')[0],
            day_name: new Date(day.date).toLocaleDateString('en-US', { weekday: 'short' }),
            profit: parseFloat(day.profit || 0).toFixed(2),
            transaction_count: parseInt(day.transaction_count || 0),
            formatted_date: new Date(day.date).toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric'
            })
        }));

        // VERCEL FIX: Calculate totals
        const totalProfit = chartData.reduce((sum, day) => sum + parseFloat(day.profit), 0);
        const averageProfit = chartData.length > 0 ? totalProfit / chartData.length : 0;
        const bestDay = chartData.reduce((best, day) =>
            parseFloat(day.profit) > parseFloat(best?.profit || 0) ? day : best, chartData[0]);

        res.json({
            success: true,
            data: {
                daily: chartData,
                summary: {
                    total_profit: totalProfit.toFixed(2),
                    average_daily_profit: averageProfit.toFixed(2),
                    total_transactions: chartData.reduce((sum, day) => sum + day.transaction_count, 0),
                    best_day: bestDay ? {
                        date: bestDay.date,
                        profit: bestDay.profit,
                        transactions: bestDay.transaction_count
                    } : null
                }
            }
        });

    } catch (error) {
        console.error('[Vercel] Error fetching profit statistics:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch profit data',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// FIXED: Dashboard Stats - VERCEL COMPATIBLE
// ============================================
app.get("/api/dashboard-stats", requireAdmin, async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];

        // VERCEL FIX: Optimized queries with better error handling
        const queries = [
            // Today's revenue
            db.promise().query(
                `SELECT COALESCE(SUM(amount_paid), 0) as today_revenue,
                        COUNT(*) as today_transactions
                 FROM payments 
                 WHERE DATE(payment_date) = CURDATE() AND status = 'Paid'`
            ),

            // Active bookings
            db.promise().query(
                `SELECT 
                    COUNT(DISTINCT reservation_id) as active_bookings_count,
                    COALESCE(SUM(
                        CASE 
                            WHEN no_of_rooms IS NULL OR no_of_rooms = '' THEN 1
                            ELSE CAST(no_of_rooms AS UNSIGNED)
                        END
                    ), 0) as total_rooms_booked,
                    COUNT(DISTINCT guest_id) as unique_guests
                 FROM reservationsdetails 
                 WHERE status IN ('Pending', 'Permitted') 
                 AND check_out >= CURDATE()`
            ),

            // Total rooms
            db.promise().query(
                `SELECT COUNT(*) as total_rooms FROM rooms`
            ),

            // Currently occupied rooms
            db.promise().query(
                `SELECT COUNT(DISTINCT room_tag_split) as booked_rooms_count
                 FROM (
                     SELECT TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(r.roomTag, ',', n.n), ',', -1)) as room_tag_split
                     FROM reservationsdetails r
                     CROSS JOIN (
                         SELECT 1 as n UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 
                         UNION SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8
                     ) n
                     WHERE (r.status = 'Permitted' OR 
                           (r.status = 'Pending' AND r.created_at >= DATE_SUB(NOW(), INTERVAL 2 HOUR)))
                     AND r.check_in <= CURDATE() AND r.check_out >= CURDATE()
                     AND r.roomTag IS NOT NULL AND r.roomTag != ''
                     AND n.n <= 1 + (LENGTH(r.roomTag) - LENGTH(REPLACE(r.roomTag, ',', '')))
                 ) as split_rooms
                 WHERE room_tag_split != ''`
            ),

            // Pending approvals
            db.promise().query(
                `SELECT COUNT(*) as pending_approvals
                 FROM reservationsdetails 
                 WHERE status = 'Pending' 
                 AND created_at >= DATE_SUB(NOW(), INTERVAL 2 HOUR)`
            ),

            // Monthly revenue
            db.promise().query(
                `SELECT COALESCE(SUM(amount_paid), 0) as month_revenue
                 FROM payments 
                 WHERE MONTH(payment_date) = MONTH(CURDATE()) 
                 AND YEAR(payment_date) = YEAR(CURDATE())
                 AND status = 'Paid'`
            )
        ];

        const results = await Promise.all(queries);

        // Parse results
        const todayRevenue = parseFloat(results[0][0][0].today_revenue || 0);
        const todayTransactions = parseInt(results[0][0][0].today_transactions || 0);
        const activeBookings = parseInt(results[1][0][0].active_bookings_count || 0);
        const totalRoomsBooked = parseInt(results[1][0][0].total_rooms_booked || 0);
        const uniqueGuests = parseInt(results[1][0][0].unique_guests || 0);
        const totalRooms = parseInt(results[2][0][0].total_rooms || 0);
        const bookedRooms = parseInt(results[3][0][0].booked_rooms_count || 0);
        const pendingApprovals = parseInt(results[4][0][0].pending_approvals || 0);
        const monthRevenue = parseFloat(results[5][0][0].month_revenue || 0);

        const availableRooms = totalRooms - bookedRooms;
        const occupancyRate = totalRooms > 0 ? Math.round((bookedRooms / totalRooms) * 100) : 0;

        res.json({
            success: true,
            stats: {
                revenue: {
                    today: todayRevenue.toFixed(2),
                    this_month: monthRevenue.toFixed(2),
                    today_transactions: todayTransactions
                },
                bookings: {
                    active: activeBookings,
                    total_rooms_booked: totalRoomsBooked,
                    pending_approvals: pendingApprovals,
                    unique_guests: uniqueGuests
                },
                rooms: {
                    total: totalRooms,
                    booked: bookedRooms,
                    available: availableRooms,
                    occupancy_rate: occupancyRate
                }
            },
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('[Vercel] Error fetching dashboard stats:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch dashboard statistics',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// FIXED: Weekly Revenue - VERCEL COMPATIBLE
// ============================================
app.get("/api/revenue-weekly", requireAdmin, async (req, res) => {
    try {
        // VERCEL FIX: Ensure consistent day ordering
        const query = `
            WITH RECURSIVE week_days AS (
                SELECT DATE_SUB(CURDATE(), INTERVAL WEEKDAY(CURDATE()) DAY) as date
                UNION ALL
                SELECT date + INTERVAL 1 DAY
                FROM week_days
                WHERE date < DATE_SUB(CURDATE(), INTERVAL WEEKDAY(CURDATE()) DAY) + INTERVAL 6 DAY
            )
            SELECT 
                week_days.date,
                DAYNAME(week_days.date) as day_name,
                DAYOFWEEK(week_days.date) as day_of_week,
                COALESCE(SUM(p.amount_paid), 0) as revenue,
                COALESCE(COUNT(p.payment_id), 0) as transaction_count
            FROM week_days
            LEFT JOIN payments p ON DATE(p.payment_date) = week_days.date AND p.status = 'Paid'
            GROUP BY week_days.date
            ORDER BY week_days.date ASC
        `;

        const [results] = await db.promise().query(query);

        // VERCEL FIX: Map to day abbreviations
        const dayMap = {
            'Monday': 'Mon',
            'Tuesday': 'Tue',
            'Wednesday': 'Wed',
            'Thursday': 'Thu',
            'Friday': 'Fri',
            'Saturday': 'Sat',
            'Sunday': 'Sun'
        };

        const labels = [];
        const revenueData = [];
        const transactionData = [];

        results.forEach(day => {
            const dayAbbr = dayMap[day.day_name] || day.day_name.substring(0, 3);
            labels.push(dayAbbr);
            revenueData.push(parseFloat(day.revenue || 0));
            transactionData.push(parseInt(day.transaction_count || 0));
        });

        // VERCEL FIX: Calculate totals
        const totalRevenue = revenueData.reduce((sum, val) => sum + val, 0);
        const averageRevenue = revenueData.length > 0 ? totalRevenue / revenueData.length : 0;
        const peakDay = results.reduce((peak, day) =>
            parseFloat(day.revenue) > parseFloat(peak?.revenue || 0) ? day : peak, results[0]);

        res.json({
            success: true,
            labels: labels,
            data: revenueData,
            transaction_counts: transactionData,
            summary: {
                total_revenue: totalRevenue.toFixed(2),
                average_daily_revenue: averageRevenue.toFixed(2),
                total_transactions: transactionData.reduce((sum, val) => sum + val, 0),
                peak_day: peakDay ? {
                    date: peakDay.date.toISOString().split('T')[0],
                    day: peakDay.day_name,
                    revenue: parseFloat(peakDay.revenue || 0).toFixed(2),
                    transactions: peakDay.transaction_count
                } : null
            },
            rawData: results
        });

    } catch (error) {
        console.error('[Vercel] Error fetching weekly revenue:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch revenue data',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// FIXED: Room Distribution - VERCEL COMPATIBLE
// ============================================
app.get("/api/room-distribution", requireAdmin, async (req, res) => {
    try {
        const period = req.query.period || 30; // Default to 30 days

        const query = `
            SELECT 
                r.room_type,
                COUNT(DISTINCT r.reservation_id) as booking_count,
                SUM(
                    CASE 
                        WHEN r.no_of_rooms IS NULL OR r.no_of_rooms = '' THEN 1
                        ELSE CAST(r.no_of_rooms AS UNSIGNED)
                    END
                ) as total_rooms,
                SUM(r.total_amount) as total_revenue,
                AVG(
                    CASE 
                        WHEN r.no_of_rooms IS NULL OR r.no_of_rooms = '' THEN 1
                        ELSE CAST(r.no_of_rooms AS UNSIGNED)
                    END
                ) as avg_rooms_per_booking
            FROM reservationsdetails r
            WHERE r.status IN ('Permitted', 'Pending')
            AND r.created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
            GROUP BY r.room_type
            ORDER BY total_rooms DESC
        `;

        const [results] = await db.promise().query(query, [parseInt(period)]);

        const roomTypeMap = {
            '5000': { name: 'Standard', color: 'rgb(52, 152, 219)' },
            '7500': { name: 'Deluxe', color: 'rgb(39, 174, 96)' },
            '12000': { name: 'Suite', color: 'rgb(243, 156, 18)' },
            '18000': { name: 'Family Suite', color: 'rgb(155, 89, 182)' }
        };

        const labels = [];
        const roomData = [];
        const revenueData = [];
        const bookingCountData = [];
        const backgroundColor = [];
        const colors = [];

        results.forEach((item, index) => {
            const roomInfo = roomTypeMap[item.room_type] || {
                name: `Room Type ${item.room_type}`,
                color: `hsl(${index * 60}, 70%, 60%)`
            };

            labels.push(roomInfo.name);
            roomData.push(parseInt(item.total_rooms || 0));
            revenueData.push(parseFloat(item.total_revenue || 0).toFixed(2));
            bookingCountData.push(parseInt(item.booking_count || 0));
            backgroundColor.push(roomInfo.color);
            colors.push(roomInfo.color.replace('rgb', 'rgba').replace(')', ', 0.2)'));
        });

        // If no data, provide sample data for UI
        if (labels.length === 0) {
            Object.entries(roomTypeMap).forEach(([key, value]) => {
                labels.push(value.name);
                roomData.push(0);
                revenueData.push('0.00');
                bookingCountData.push(0);
                backgroundColor.push(value.color);
                colors.push(value.color.replace('rgb', 'rgba').replace(')', ', 0.2)'));
            });
        }

        // Calculate totals
        const totalRooms = roomData.reduce((sum, val) => sum + val, 0);
        const totalRevenue = revenueData.reduce((sum, val) => sum + parseFloat(val), 0);
        const totalBookings = bookingCountData.reduce((sum, val) => sum + val, 0);

        res.json({
            success: true,
            labels: labels,
            data: roomData,
            revenue_data: revenueData,
            booking_counts: bookingCountData,
            backgroundColor: backgroundColor,
            borderColor: backgroundColor,
            hoverBackgroundColor: colors,
            summary: {
                total_rooms: totalRooms,
                total_revenue: totalRevenue.toFixed(2),
                total_bookings: totalBookings,
                period_days: period,
                average_rooms_per_booking: totalBookings > 0 ? (totalRooms / totalBookings).toFixed(1) : 0
            },
            rawData: results,
            note: "Data shows room type distribution for the selected period"
        });

    } catch (error) {
        console.error('[Vercel] Error fetching room distribution:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch room distribution data',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// FIXED: Dashboard Recent Bookings - VERCEL COMPATIBLE
// ============================================
app.get("/api/dashboard/recent-bookings", requireAdmin, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 5;

        // VERCEL FIX: Enhanced query with more details
        const query = `
            SELECT 
                r.reservation_id,
                gd.first_name,
                gd.last_name,
                gd.email,
                gd.nationality,
                gd.phone_number,
                
                r.room_type,
                r.bedding_type,
                r.meal_plan,
                r.no_of_rooms,
                r.check_in,
                r.check_out,
                r.roomTag,
                r.status,
                r.total_amount,
                r.created_at,
                r.nights,
                
                COALESCE(
                    (SELECT p.amount_paid 
                     FROM payments p 
                     WHERE p.reservation_id = r.reservation_id 
                     AND p.status = 'Paid'
                     ORDER BY p.payment_date DESC 
                     LIMIT 1), 
                0.00) as amount_paid,
                
                COALESCE(
                    (SELECT p.status 
                     FROM payments p 
                     WHERE p.reservation_id = r.reservation_id 
                     ORDER BY p.payment_date DESC 
                     LIMIT 1), 
                'Pending') as payment_status,
                
                COALESCE(
                    (SELECT p.payment_method 
                     FROM payments p 
                     WHERE p.reservation_id = r.reservation_id 
                     AND p.status = 'Paid'
                     ORDER BY p.payment_date DESC 
                     LIMIT 1), 
                NULL) as payment_method
                
            FROM reservationsdetails r
            LEFT JOIN guestdetails gd ON r.guest_id = gd.guest_id
            ORDER BY r.created_at DESC
            LIMIT ?
        `;

        const [results] = await db.promise().query(query, [limit]);

        const roomTypeMap = {
            '5000': 'Standard',
            '7500': 'Deluxe',
            '12000': 'Suite',
            '18000': 'Family Suite'
        };

        const bookings = results.map(booking => {
            // Parse room tags
            let roomCount = 1;
            let roomsArray = [];
            if (booking.roomTag) {
                roomsArray = booking.roomTag.split(',')
                    .map(r => r.trim())
                    .filter(r => r);
                roomCount = roomsArray.length;
            }

            // Calculate stay duration
            let nights = booking.nights || 0;
            if (!nights && booking.check_in && booking.check_out) {
                const checkIn = new Date(booking.check_in);
                const checkOut = new Date(booking.check_out);
                nights = Math.max(1, Math.ceil((checkOut - checkIn) / (1000 * 60 * 60 * 24)));
            }

            // Calculate financials
            const totalAmount = parseFloat(booking.total_amount || 0);
            const amountPaid = parseFloat(booking.amount_paid || 0);
            const amountDue = totalAmount - amountPaid;

            return {
                // Core booking info
                reservation_id: booking.reservation_id,

                // Guest info
                guest: {
                    name: `${booking.first_name || ''} ${booking.last_name || ''}`.trim() || 'N/A',
                    email: booking.email || 'N/A',
                    nationality: booking.nationality || 'N/A',
                    phone: booking.phone_number || 'N/A'
                },

                // Room details
                room: {
                    type: booking.room_type,
                    type_label: roomTypeMap[booking.room_type] || `Room ${booking.room_type}`,
                    bedding: booking.bedding_type,
                    meal_plan: booking.meal_plan,
                    tags: roomsArray,
                    tag_display: booking.roomTag || 'Not assigned',
                    room_count: roomCount,
                    booked_rooms: booking.no_of_rooms || 1
                },

                // Dates
                dates: {
                    check_in: booking.check_in ? new Date(booking.check_in).toISOString().split('T')[0] : null,
                    check_in_formatted: booking.check_in ? new Date(booking.check_in).toLocaleDateString() : 'N/A',
                    check_out: booking.check_out ? new Date(booking.check_out).toISOString().split('T')[0] : null,
                    check_out_formatted: booking.check_out ? new Date(booking.check_out).toLocaleDateString() : 'N/A',
                    nights: nights,
                    booked_at: booking.created_at ? new Date(booking.created_at).toISOString() : null,
                    booked_at_formatted: booking.created_at ? new Date(booking.created_at).toLocaleString() : 'N/A'
                },

                // Status
                status: {
                    reservation: booking.status || 'Pending',
                    payment: booking.payment_status || 'Pending',
                    payment_method: booking.payment_method
                },

                // Financial
                financial: {
                    total_amount: totalAmount.toFixed(2),
                    amount_paid: amountPaid.toFixed(2),
                    amount_due: amountDue.toFixed(2),
                    is_fully_paid: amountDue <= 0,
                    payment_progress: totalAmount > 0 ? Math.round((amountPaid / totalAmount) * 100) : 0
                },

                // Computed flags
                is_active: booking.status === 'Permitted' ||
                    (booking.status === 'Pending' &&
                        booking.created_at &&
                        (new Date() - new Date(booking.created_at)) < 2 * 60 * 60 * 1000),
                is_urgent: booking.status === 'Pending' &&
                    booking.created_at &&
                    (new Date() - new Date(booking.created_at)) >= 1.5 * 60 * 60 * 1000
            };
        });

        // Calculate summary statistics
        const summary = {
            total_bookings: bookings.length,
            total_revenue: bookings.reduce((sum, b) => sum + parseFloat(b.financial.amount_paid), 0).toFixed(2),
            pending_payments: bookings.filter(b => b.status.payment === 'Pending').length,
            active_bookings: bookings.filter(b => b.is_active).length
        };

        res.json({
            success: true,
            bookings: bookings,
            summary: summary,
            meta: {
                limit: limit,
                timestamp: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('[Vercel] Error fetching recent bookings:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch recent bookings',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================
// HELPER FUNCTIONS - Keep these at the bottom
// ============================================

function getRoomTypeLabel(value) {
    const roomTypes = {
        '5000': 'Standard Room',
        '7500': 'Deluxe Room',
        '12000': 'Suite',
        '18000': 'Family Suite'
    };
    return roomTypes[value] || value || 'N/A';
}

function getBedTypeLabel(value) {
    const bedTypes = {
        '0': 'No Bed',
        '100': 'Single Bed',
        '150': 'Double Bed',
        '200': 'King Size Bed',
        '250': 'Twin Beds'
    };
    return bedTypes[value] || value || 'N/A';
}

function getMealPlanLabel(value) {
    const mealPlans = {
        '0': 'No Meals',
        '500': 'Breakfast Only',
        '1200': 'Half Board',
        '2000': 'Full Board'
    };
    return mealPlans[value] || value || 'N/A';
}


// Export for Vercel serverless
module.exports = app;