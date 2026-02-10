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



app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        sameSite: 'lax'
    }
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




app.use("/Styles", express.static(path.join(__dirname, "Styles")));
app.use("/vid", express.static(path.join(__dirname, "vid")));
app.use("/Images", express.static(path.join(__dirname, "images")));
app.use("/icons", express.static(path.join(__dirname, "icons")));


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


publicPages.forEach(route => {
    app.get(route, (req, res) => {

        if (route === "/adminlogin" || route === "/guestlogin") {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }

        res.sendFile(path.join(__dirname, htmlFiles[route]));
    });
});


userProtectedPages.forEach(route => {
    app.get(route, requireLogin, (req, res) => {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.sendFile(path.join(__dirname, htmlFiles[route]));
    });
});

adminProtectedPages.forEach(route => {
    app.get(route, requireAdmin, (req, res) => {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.sendFile(path.join(__dirname, htmlFiles[route]));
    });
});


app.get("/api/session-user", (req, res) => {
    if (req.session && req.session.user) {
        return res.json(req.session.user);
    }
    return res.status(401).json({ message: "Not logged in" });
});



app.get("/api/admin/check", (req, res) => {
    if (req.session.admin) {
        res.json({ loggedIn: true, adminId: req.session.admin.adminId });
    } else {
        res.json({ loggedIn: false });
    }
});

app.get("/api/user/check", (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, email: req.session.user.email });
    } else {
        res.json({ loggedIn: false });
    }
});


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


app.get("/adminlogout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("Error destroying session:", err);
            return res.status(500).send("Logout failed");
        }


        res.clearCookie("connect.sid");
        res.clearCookie("session");
        res.clearCookie("sessionId");


        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');

        res.redirect("/adminlogin");
    });
});

app.get("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("Logout error:", err);
            return res.status(500).send("Failed to logout");
        }


        res.clearCookie("connect.sid");
        res.clearCookie("session");
        res.clearCookie("sessionId");


        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');

        res.redirect("/guestlogin");
    });
});

app.get("/api/reservations", (req, res) => {
    if (!req.session.user)
        return res.status(401).json({ message: "Not logged in" });

    const email = req.session.user.email;

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
            -- Only sum PAID payments
            COALESCE(
                (SELECT SUM(p2.amount_paid) 
                 FROM payments p2 
                 WHERE p2.reservation_id = r.reservation_id 
                 AND p2.status = 'Paid'), 
            0.00) AS amount_paid,
            -- Calculate amount due
            (r.total_amount - COALESCE(
                (SELECT SUM(p2.amount_paid) 
                 FROM payments p2 
                 WHERE p2.reservation_id = r.reservation_id 
                 AND p2.status = 'Paid'), 
            0.00)) AS amount_due,
            -- Get latest payment status (but only consider Paid status for payment purposes)
            CASE 
                WHEN EXISTS (
                    SELECT 1 FROM payments p3 
                    WHERE p3.reservation_id = r.reservation_id 
                    AND p3.status = 'Paid'
                ) THEN 'Paid'
                ELSE 'Pending'
            END AS payment_status,
            -- Get latest payment method from paid payments
            COALESCE(
                (SELECT p4.payment_method 
                 FROM payments p4 
                 WHERE p4.reservation_id = r.reservation_id 
                 AND p4.status = 'Paid'
                 ORDER BY p4.payment_date DESC 
                 LIMIT 1), 
            NULL) AS payment_method,
            -- Time-based calculations for pending reservations
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
            -- Calculate if 2 hours have passed (expired)
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
            -- Calculate time left for pending reservations without payment
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

    db.query(sql, [email], (err, results) => {
        if (err) {
            console.error("Reservations fetch error:", err);
            return res.status(500).json({ message: "Database error" });
        }

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
                is_expired: Boolean(reservation.is_expired)
            };
        });

        res.json(formattedResults);
    });
});

app.get("/api/new-bookings", requireAdmin, (req, res) => {
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
            -- Add calculated fields
            CASE 
                WHEN r.no_of_rooms > 1 THEN CONCAT(r.no_of_rooms, ' rooms')
                ELSE '1 room'
            END as rooms_display
        FROM reservationsdetails r
        LEFT JOIN guestdetails gd ON r.guest_id = gd.guest_id
        ORDER BY r.created_at DESC
    `;

    if (limit && !isNaN(limit)) {
        sql += ` LIMIT ${parseInt(limit)}`;
    }

    db.query(sql, (err, results) => {
        if (err) {
            console.error("Bookings fetch error:", err);
            return res.status(500).json({ error: "Database error", details: err });
        }


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
                has_multiple_rooms: roomCount > 1
            };
        });

        res.json(enhancedResults);
    });
});

app.get("/api/bookedRooms", (req, res) => {
    const sql = `SELECT reservation_id, roomTag, room_type FROM reservationsdetails ORDER BY reservation_id DESC`;
    db.query(sql, (err, results) => {
        if (err) {
            console.error("BookedRooms error:", err);
            return res.status(500).send("Error fetching booked rooms");
        }
        res.json(results);
    });
});






app.patch("/api/reservations/:id/permit", requireAdmin, async (req, res) => {
    const reservationId = req.params.id;

    try {

        await db.promise().query("START TRANSACTION");


        const [reservationRows] = await db.promise().query(
            `SELECT r.reservation_id, r.guest_id, r.total_amount, 
                    gd.first_name, gd.last_name, gd.email
             FROM reservationsdetails r
             JOIN guestdetails gd ON r.guest_id = gd.guest_id
             WHERE r.reservation_id = ?`,
            [reservationId]
        );

        if (reservationRows.length === 0) {
            await db.promise().query("ROLLBACK");
            return res.status(404).json({ message: "Reservation not found" });
        }

        const reservation = reservationRows[0];
        const guestId = reservation.guest_id;
        const totalAmount = reservation.total_amount;
        const paymentMethod = 'Cash';

        console.log(`Permitting reservation ${reservationId} for guest ${guestId}, amount: ${totalAmount}`);


        const [existingPayments] = await db.promise().query(
            "SELECT payment_id FROM payments WHERE reservation_id = ?",
            [reservationId]
        );

        let paymentId;

        if (existingPayments.length > 0) {

            await db.promise().query(
                `UPDATE payments 
                 SET status = 'Paid', 
                     amount_paid = ?,
                     payment_method = ?,
                     payment_date = NOW()
                 WHERE reservation_id = ?`,
                [totalAmount, paymentMethod, reservationId]
            );
            paymentId = existingPayments[0].payment_id;
            console.log(`Updated existing payment ${paymentId} to Paid`);
        } else {

            const [paymentResult] = await db.promise().query(
                `INSERT INTO payments 
                 (reservation_id, guest_id, amount_paid, payment_method, status, payment_date)
                 VALUES (?, ?, ?, ?, 'Paid', NOW())`,
                [reservationId, guestId, totalAmount, paymentMethod]
            );
            paymentId = paymentResult.insertId;
            console.log(`Created new payment ${paymentId} with amount ${totalAmount}`);
        }


        const [updateResult] = await db.promise().query(
            "UPDATE reservationsdetails SET status = 'Permitted' WHERE reservation_id = ?",
            [reservationId]
        );


        await db.promise().query("COMMIT");

        res.json({
            success: true,
            message: "Reservation permitted and payment recorded successfully",
            reservationId: reservationId,
            paymentId: paymentId,
            paymentAmount: totalAmount,
            paymentMethod: paymentMethod,
            guestName: `${reservation.first_name} ${reservation.last_name}`,
            guestEmail: reservation.email
        });

    } catch (err) {
        console.error("Permit error:", err);
        await db.promise().query("ROLLBACK");
        res.status(500).json({
            success: false,
            message: "Server error",
            error: err.message
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



app.get("/api/guestlogin", (req, res) => {
    if (!req.session.user) {

        return res.status(401).json({ message: "Not logged in" });
    }


    res.json({
        guest_id: req.session.user.guest_id,
        username: req.session.user.username,
        email: req.session.user.email
    });
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

app.get("/api/rooms", (req, res) => {
    db.query("SELECT * FROM rooms ORDER BY roomTag ASC", (err, results) => {
        if (err) {
            console.error("Fetch rooms error:", err);
            return res.status(500).send("Error fetching rooms");
        }
        res.json(results);
    });
});



app.get("/admin-simple", requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, "admin-simple.html"));
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


app.get("/api/table-bookings", (req, res) => {
    const sql = "SELECT * FROM table_bookings ORDER BY created_at DESC";
    db.query(sql, (err, results) => {
        if (err) {
            console.error("Fetch table bookings error:", err);
            return res.status(500).json({ message: "Database error" });
        }
        res.json(results);
    });
});

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


app.get("/admin/subscribers", (req, res) => {
    db.query("SELECT * FROM newsletter", (err, results) => {
        if (err) return res.json([]);
        res.json(results);
    });
});

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




app.get("/api/dashboard/recent-bookings", requireAdmin, async (req, res) => {
    try {
        const limit = req.query.limit || 5;

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
                'Pending') as payment_status
            FROM reservationsdetails r
            LEFT JOIN guestdetails gd ON r.guest_id = gd.guest_id
            -- Only show bookings that are still active (check_out date is in the future)
            WHERE r.check_out >= CURDATE()
            -- OR if you want to show completed bookings for a short period after checkout:
            -- WHERE r.check_out >= DATE_SUB(CURDATE(), INTERVAL 2 DAY)
            ORDER BY r.created_at DESC
            LIMIT ?
        `;

        const [results] = await db.promise().query(query, [parseInt(limit)]);

        const bookings = results.map(booking => {
            const roomTypeMap = {
                '5000': 'Standard',
                '7500': 'Deluxe',
                '12000': 'Suite',
                '18000': 'Family Suite'
            };

            let roomCount = 1;
            if (booking.roomTag) {
                const rooms = booking.roomTag.split(',').map(r => r.trim()).filter(r => r);
                roomCount = rooms.length;
            }

            return {
                ...booking,
                room_type_label: roomTypeMap[booking.room_type] || `Room (${booking.room_type})`,
                guest_name: `${booking.first_name || ''} ${booking.last_name || ''}`.trim(),
                booking_date: booking.created_at,
                room_count: roomCount,
                rooms_display: booking.roomTag,

                is_active: new Date(booking.check_out) >= new Date()
            };
        });

        res.json({
            success: true,
            bookings: bookings
        });

    } catch (error) {
        console.error('Error fetching recent bookings:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch recent bookings'
        });
    }
});

app.get("/api/available-rooms", async (req, res) => {
    try {
        const { checkIn, checkOut, roomType } = req.query;

        if (!checkIn || !checkOut) {
            return res.status(400).json({
                success: false,
                message: "Check-in and check-out dates are required"
            });
        }


        const query = `
            SELECT roomTag 
            FROM reservationsdetails 
            WHERE (
                -- Permitted reservations (always booked)
                (status = 'Permitted')
                OR 
                -- Pending reservations less than 2 hours old
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


        const bookedTags = new Set();

        bookedReservations.forEach(reservation => {
            if (reservation.roomTag) {

                const tags = reservation.roomTag.split(',').map(tag => tag.trim());
                tags.forEach(tag => {
                    if (tag) bookedTags.add(tag);
                });
            }
        });


        const bookedTagsArray = Array.from(bookedTags);


        const [allRooms] = await db.promise().query(
            "SELECT roomTag FROM rooms ORDER BY roomTag ASC"
        );

        const roomStatus = allRooms.map(room => ({
            roomTag: room.roomTag,
            isAvailable: !bookedTagsArray.includes(room.roomTag)
        }));

        res.json({
            success: true,
            bookedRooms: bookedTagsArray,
            roomStatus: roomStatus,
            totalRooms: allRooms.length,
            availableRooms: allRooms.length - bookedTagsArray.length
        });

    } catch (error) {
        console.error('Error fetching room availability:', error);
        res.status(500).json({
            success: false,
            message: "Failed to check room availability"
        });
    }
});


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


        const query = `
            SELECT COUNT(*) as count 
            FROM reservationsdetails 
            WHERE (
                -- Permitted reservations (always booked)
                (status = 'Permitted')
                OR 
                -- Pending reservations less than 2 hours old
                (status = 'Pending' AND created_at >= DATE_SUB(NOW(), INTERVAL 2 HOUR))
            )
            AND (
                (check_in <= ? AND check_out >= ?) OR
                (check_in <= ? AND check_out >= ?) OR
                (check_in >= ? AND check_out <= ?)
            )
            AND (
                roomTag = ? 
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
            roomTag
        ]);

        const isAvailable = result[0].count === 0;

        res.json({
            success: true,
            roomTag: roomTag,
            isAvailable: isAvailable,
            bookedCount: result[0].count
        });

    } catch (error) {
        console.error('Error checking room availability:', error);
        res.status(500).json({
            success: false,
            message: "Failed to check room availability"
        });
    }
});



app.get("/api/payment/:reservationId", (req, res) => {
    const { reservationId } = req.params;

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
            -- Only sum confirmed payments
            COALESCE(
                (SELECT SUM(p2.amount_paid) 
                 FROM payments p2 
                 WHERE p2.reservation_id = r.reservation_id 
                 AND p2.status = 'Paid'), 
            0.00) AS amount_paid,
            -- Get latest payment status
            COALESCE(
                (SELECT p3.status 
                 FROM payments p3 
                 WHERE p3.reservation_id = r.reservation_id 
                 ORDER BY p3.payment_date DESC 
                 LIMIT 1), 
            'Pending') AS payment_status,
            -- Get latest payment method
            COALESCE(
                (SELECT p4.payment_method 
                 FROM payments p4 
                 WHERE p4.reservation_id = r.reservation_id 
                 ORDER BY p4.payment_date DESC 
                 LIMIT 1), 
            NULL) AS payment_method
        FROM reservationsdetails r
        WHERE r.reservation_id = ?
        LIMIT 1
    `;

    db.query(sql, [reservationId], (err, results) => {
        if (err) {
            console.error("payment fetch error:", err);
            return res.status(500).json({ message: "Database error." });
        }
        if (results.length === 0) return res.status(404).json({ message: "Reservation not found." });
        res.json(results[0]);
    });
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


app.get("/api/reservations/:id", (req, res) => {
    const id = req.params.id;
    const sql = `
        SELECT 
          r.reservation_id,
          r.room_type, r.bedding_type, r.no_of_rooms, r.meal_plan, r.check_in, r.check_out, r.status,
          g.title, g.first_name, g.last_name, g.email, g.nationality, g.passport_country, g.phone_number,
          COALESCE(p.amount_paid, 0.00) AS amount_paid,
          p.status AS payment_status,
          p.payment_method
        FROM reservationsdetails r
        LEFT JOIN guestdetails g ON r.guest_id = g.guest_id
        LEFT JOIN payments p ON r.reservation_id = p.reservation_id
        WHERE r.reservation_id = ?
        LIMIT 1
    `;
    db.query(sql, [id], (err, results) => {
        if (err) {
            console.error("single reservation error:", err);
            return res.status(500).json({ error: err.sqlMessage || err });
        }
        if (results.length === 0) return res.status(404).json({ message: "Reservation not found" });
        res.json(results[0]);
    });
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




app.get("/api/guestdetails", async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ message: "Not logged in" });
    }

    const email = req.session.user.email;

    const [rows] = await db.promise().query(
        "SELECT * FROM guestdetails WHERE email = ? LIMIT 1",
        [email]
    );

    if (!rows.length) {
        return res.status(404).json({ message: "Guest not found" });
    }

    res.json(rows[0]);
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


app.get("/api/payments", requireAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 10, search = '' } = req.query;
        const offset = (page - 1) * limit;

        let baseQuery = `
            SELECT 
                r.reservation_id,
                gd.first_name,
                gd.last_name,
                gd.email,
                r.room_type,
                r.bedding_type,
                r.check_in,
                r.check_out,
                r.no_of_rooms,
                r.meal_plan,
                r.roomTag,
                r.nights,
                r.total_amount,
                p.payment_id,
                p.amount_paid,
                p.payment_method,
                p.payment_date,
                p.status as payment_status
            FROM reservationsdetails r
            JOIN guestdetails gd ON r.guest_id = gd.guest_id
            LEFT JOIN payments p ON r.reservation_id = p.reservation_id
            WHERE p.status = 'Paid'
        `;

        let countQuery = `
            SELECT COUNT(*) as total
            FROM reservationsdetails r
            JOIN guestdetails gd ON r.guest_id = gd.guest_id
            LEFT JOIN payments p ON r.reservation_id = p.reservation_id
            WHERE p.status = 'Paid'
        `;

        const queryParams = [];
        const countParams = [];

        if (search) {
            baseQuery += ` AND (
                gd.first_name LIKE ? OR 
                gd.last_name LIKE ? OR 
                gd.email LIKE ? OR 
                r.roomTag LIKE ? OR
                p.payment_method LIKE ?
            )`;

            countQuery += ` AND (
                gd.first_name LIKE ? OR 
                gd.last_name LIKE ? OR 
                gd.email LIKE ? OR 
                r.roomTag LIKE ? OR
                p.payment_method LIKE ?
            )`;

            const searchParam = `%${search}%`;
            queryParams.push(searchParam, searchParam, searchParam, searchParam, searchParam);
            countParams.push(searchParam, searchParam, searchParam, searchParam, searchParam);
        }

        baseQuery += ` ORDER BY p.payment_date DESC LIMIT ? OFFSET ?`;
        queryParams.push(parseInt(limit), offset);


        const [countResult] = await db.promise().query(countQuery, countParams);
        const total = countResult[0]?.total || 0;

        const [payments] = await db.promise().query(baseQuery, queryParams);

        const paymentsWithDetails = payments.map(payment => {

            const roomRent = parseNumericValue(payment.room_type);
            const bedRent = parseNumericValue(payment.bedding_type);
            const mealCost = parseNumericValue(payment.meal_plan);
            const nights = parseInt(payment.nights) || 1;
            const rooms = parseInt(payment.no_of_rooms) || 1;

            const roomTotal = (roomRent * rooms * nights).toFixed(2);
            const bedTotal = (bedRent * rooms * nights).toFixed(2);
            const mealTotal = (mealCost * rooms * nights).toFixed(2);

            return {
                ...payment,
                name: `${payment.first_name} ${payment.last_name}`,
                email: payment.email,
                room_rent: roomTotal,
                bed_rent: bedTotal,
                meals: mealTotal,
                gr_total: parseFloat(payment.amount_paid || payment.total_amount || 0).toFixed(2),
                payment_method: payment.payment_method || 'Mpesa',
                payment_date: payment.payment_date
            };
        });

        res.json({
            success: true,
            payments: paymentsWithDetails,
            total,
            page: parseInt(page),
            totalPages: Math.ceil(total / limit),
            limit: parseInt(limit)
        });

    } catch (error) {
        console.error('Error fetching payments:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch payment records',
            error: error.message
        });
    }
});


function parseNumericValue(value) {
    if (!value) return 0;


    if (!isNaN(value) && !isNaN(parseFloat(value))) {
        return parseFloat(value);
    }


    const numericMatch = String(value).match(/(\d+(\.\d+)?)/);
    return numericMatch ? parseFloat(numericMatch[1]) : 0;
}


app.get("/api/payment/receipt/:reservationId", requireAdmin, async (req, res) => {
    try {
        const { reservationId } = req.params;

        const query = `
            SELECT 
                r.reservation_id,
                gd.title,
                gd.first_name,
                gd.last_name,
                gd.email,
                gd.phone_number,
                gd.national_id,
                gd.passport_no,
                gd.nationality,
                r.room_type,
                r.bedding_type,
                r.check_in,
                r.check_out,
                r.no_of_rooms,
                r.meal_plan,
                r.roomTag,
                r.nights,
                r.total_amount,
                p.amount_paid,
                p.payment_method,
                p.payment_date,
                p.status as payment_status
            FROM reservationsdetails r
            JOIN guestdetails gd ON r.guest_id = gd.guest_id
            LEFT JOIN payments p ON r.reservation_id = p.reservation_id
            WHERE r.reservation_id = ? AND p.status = 'Paid'
            ORDER BY p.payment_date DESC
            LIMIT 1
        `;

        const [results] = await db.promise().query(query, [reservationId]);

        if (results.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Payment receipt not found'
            });
        }

        const payment = results[0];


        const roomRent = parseNumericValue(payment.room_type);
        const bedRent = parseNumericValue(payment.bedding_type);
        const mealCost = parseNumericValue(payment.meal_plan);
        const nights = parseInt(payment.nights) || 1;
        const rooms = parseInt(payment.no_of_rooms) || 1;

        const receipt = {
            reservation_id: payment.reservation_id,
            receipt_date: new Date().toISOString().split('T')[0],
            hotel_name: "THE JACKS' HOTEL",
            hotel_address: "123 Hotel Street, Nairobi, Kenya",
            hotel_phone: "+254 700 000 000",
            hotel_email: "info@thejacks.com",

            guest_info: {
                name: `${payment.title || ''} ${payment.first_name} ${payment.last_name}`.trim(),
                email: payment.email,
                phone: payment.phone_number,
                nationality: payment.nationality,
                id_number: payment.national_id || payment.passport_no || 'N/A'
            },

            booking_info: {
                check_in: formatDateForReceipt(payment.check_in),
                check_out: formatDateForReceipt(payment.check_out),
                nights: nights,
                room_tag: payment.roomTag,
                room_type: getRoomTypeDescription(payment.room_type),
                bed_type: getBedTypeDescription(payment.bedding_type),
                meal_plan: getMealPlanDescription(payment.meal_plan),
                no_of_rooms: rooms
            },

            pricing: {
                room_rate: roomRent,
                bed_rate: bedRent,
                meal_rate: mealCost,

                room_total: (roomRent * rooms * nights).toFixed(2),
                bed_total: (bedRent * rooms * nights).toFixed(2),
                meal_total: (mealCost * rooms * nights).toFixed(2),

                subtotal: payment.total_amount,
                tax_rate: "0%",
                tax_amount: "0.00",
                grand_total: parseFloat(payment.amount_paid || payment.total_amount || 0).toFixed(2)
            },

            payment_info: {
                amount_paid: parseFloat(payment.amount_paid || 0).toFixed(2),
                payment_method: payment.payment_method || 'Mpesa',
                payment_date: formatDateForReceipt(payment.payment_date),
                payment_status: payment.payment_status || 'Paid',
                transaction_id: `PAY-${payment.reservation_id}-${Date.now()}`
            }
        };

        res.json({
            success: true,
            receipt
        });

    } catch (error) {
        console.error('Error generating receipt:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to generate receipt',
            error: error.message
        });
    }
});


function formatDateForReceipt(dateString) {
    if (!dateString) return 'N/A';
    try {
        const date = new Date(dateString);
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
        '300': 'Standard Room - Queen bed, AC, TV',
        '500': 'Deluxe Room - King bed, AC, TV, Mini-bar',
        '800': 'Suite - King bed, Living area, Jacuzzi',
        '1200': 'Executive Suite - Two bedrooms, Kitchenette, Balcony'
    };
    return descriptions[value] || `Room Type (${value})`;
}

function getBedTypeDescription(value) {
    const descriptions = {
        '100': 'Single Bed',
        '150': 'Double Bed',
        '200': 'King Size Bed'
    };
    return descriptions[value] || `Bed Type (${value})`;
}

function getMealPlanDescription(value) {
    const descriptions = {
        '50': 'Breakfast Only - Continental breakfast',
        '100': 'Half Board - Breakfast & Dinner',
        '150': 'Full Board - Breakfast, Lunch & Dinner'
    };
    return descriptions[value] || `Meal Plan (${value})`;
}


app.get("/api/payment-statistics", requireAdmin, async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];
        const thisMonth = new Date().getMonth() + 1;
        const thisYear = new Date().getFullYear();


        const queries = [

            db.promise().query(
                `SELECT 
                    COUNT(*) as count,
                    COALESCE(SUM(amount_paid), 0) as total
                 FROM payments 
                 WHERE DATE(payment_date) = ? AND status = 'Paid'`,
                [today]
            ),


            db.promise().query(
                `SELECT 
                    COUNT(*) as count,
                    COALESCE(SUM(amount_paid), 0) as total
                 FROM payments 
                 WHERE MONTH(payment_date) = ? AND YEAR(payment_date) = ? AND status = 'Paid'`,
                [thisMonth, thisYear]
            ),


            db.promise().query(
                `SELECT 
                    COUNT(*) as total_count,
                    COALESCE(SUM(amount_paid), 0) as overall_total
                 FROM payments WHERE status = 'Paid'`
            ),


            db.promise().query(
                `SELECT 
                    payment_method,
                    COUNT(*) as count,
                    COALESCE(SUM(amount_paid), 0) as total
                 FROM payments 
                 WHERE status = 'Paid'
                 GROUP BY payment_method
                 ORDER BY total DESC`
            ),


            db.promise().query(
                `SELECT 
                    DATE(payment_date) as date,
                    COUNT(*) as count,
                    COALESCE(SUM(amount_paid), 0) as total
                 FROM payments 
                 WHERE payment_date >= DATE_SUB(NOW(), INTERVAL 7 DAY) AND status = 'Paid'
                 GROUP BY DATE(payment_date)
                 ORDER BY date DESC`
            )
        ];

        const results = await Promise.all(queries);

        const statistics = {
            today: {
                count: results[0][0][0].count,
                total: parseFloat(results[0][0][0].total).toFixed(2)
            },
            this_month: {
                count: results[1][0][0].count,
                total: parseFloat(results[1][0][0].total).toFixed(2)
            },
            overall: {
                count: results[2][0][0].total_count,
                total: parseFloat(results[2][0][0].overall_total).toFixed(2)
            },
            methods: results[3][0],
            recent_days: results[4][0]
        };

        res.json({
            success: true,
            statistics
        });

    } catch (error) {
        console.error('Error fetching payment statistics:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch payment statistics'
        });
    }
});


app.get("/api/payments/export", requireAdmin, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;

        let query = `
            SELECT 
                p.payment_id,
                p.reservation_id,
                CONCAT(gd.first_name, ' ', gd.last_name) as guest_name,
                gd.email,
                r.roomTag,
                r.room_type,
                r.bedding_type,
                r.meal_plan,
                r.check_in,
                r.check_out,
                r.nights,
                r.no_of_rooms,
                p.amount_paid,
                p.payment_method,
                p.payment_date,
                p.status
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


        const csvHeaders = [
            'Payment ID', 'Reservation ID', 'Guest Name', 'Email', 'Room Tag',
            'Room Type', 'Bed Type', 'Meal Plan', 'Check In', 'Check Out',
            'Nights', 'Rooms', 'Amount Paid', 'Payment Method', 'Payment Date', 'Status'
        ];

        const csvRows = payments.map(p => [
            p.payment_id,
            p.reservation_id,
            `"${p.guest_name}"`,
            p.email,
            p.roomTag,
            p.room_type,
            p.bedding_type,
            p.meal_plan,
            p.check_in,
            p.check_out,
            p.nights,
            p.no_of_rooms,
            p.amount_paid,
            p.payment_method,
            p.payment_date,
            p.status
        ]);

        const csvContent = [
            csvHeaders.join(','),
            ...csvRows.map(row => row.join(','))
        ].join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=payments_export.csv');
        res.send(csvContent);

    } catch (error) {
        console.error('Error exporting payments:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to export payment data'
        });
    }
});


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

app.get("/api/payment/receipt/:reservationId", requireAdmin, async (req, res) => {
    try {
        const { reservationId } = req.params;

        const query = `
            SELECT 
                r.reservation_id,
                gd.title,
                gd.first_name,
                gd.last_name,
                gd.email,
                gd.phone_number,
                gd.national_id,
                gd.passport_no,
                r.room_type,
                r.bedding_type,
                r.check_in,
                r.check_out,
                r.no_of_rooms,
                r.meal_plan,
                r.roomTag,
                r.nights,
                r.total_amount,
                p.amount_paid,
                p.payment_method,
                p.payment_date,
                p.mpesa_receipt,
                p.status as payment_status
            FROM reservationsdetails r
            JOIN guestdetails gd ON r.guest_id = gd.guest_id
            JOIN payments p ON r.reservation_id = p.reservation_id
            WHERE r.reservation_id = ? AND p.status = 'Paid'
            LIMIT 1
        `;

        const [results] = await db.promise().query(query, [reservationId]);

        if (results.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Payment receipt not found'
            });
        }

        const payment = results[0];


        const roomRent = parseFloat(payment.room_type) || 0;
        const bedRent = parseFloat(payment.bedding_type) || 0;
        const mealCost = parseFloat(payment.meal_plan) || 0;

        const receipt = {
            reservation_id: payment.reservation_id,
            receipt_date: new Date().toISOString().split('T')[0],
            guest_name: `${payment.title} ${payment.first_name} ${payment.last_name}`,
            guest_email: payment.email,
            guest_phone: payment.phone_number,
            guest_id: payment.national_id || payment.passport_no || 'N/A',
            check_in: payment.check_in,
            check_out: payment.check_out,
            nights: payment.nights,
            room_tag: payment.roomTag,
            room_type: getRoomTypeLabel(payment.room_type),
            bed_type: getBedTypeLabel(payment.bedding_type),
            meal_plan: getMealPlanLabel(payment.meal_plan),
            no_of_rooms: payment.no_of_rooms,


            room_rent_per_night: roomRent,
            bed_rent_per_night: bedRent,
            meal_cost_per_night: mealCost,


            total_room_rent: (roomRent * payment.no_of_rooms * payment.nights).toFixed(2),
            total_bed_rent: (bedRent * payment.no_of_rooms * payment.nights).toFixed(2),
            total_meals: (mealCost * payment.no_of_rooms * payment.nights).toFixed(2),
            grand_total: parseFloat(payment.total_amount).toFixed(2),


            amount_paid: parseFloat(payment.amount_paid).toFixed(2),
            payment_method: payment.payment_method,
            payment_date: payment.payment_date,
            transaction_id: payment.mpesa_receipt || 'N/A',
            payment_status: payment.payment_status
        };

        res.json({
            success: true,
            receipt
        });

    } catch (error) {
        console.error('Error generating receipt:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to generate receipt'
        });
    }
});


function getRoomTypeLabel(value) {
    const roomTypes = {
        '5000': 'Standard Room',
        '7500': 'Deluxe Room',
        '12000': 'Suite',
        '18000': 'Family Suite'
    };
    return roomTypes[value] || value;
}

function getBedTypeLabel(value) {
    const bedTypes = {
        '0': 'Single',
        '100': 'Twin',
        '200': 'Double',
        '300': 'King'
    };
    return bedTypes[value] || value;
}

function getMealPlanLabel(value) {
    const mealPlans = {
        '0': 'None',
        '500': 'Breakfast Only',
        '1200': 'Half Board',
        '2000': 'Full Board'
    };
    return mealPlans[value] || value;
}


app.get("/api/notifications/count", requireLogin, async (req, res) => {
    try {
        const email = req.session.user.email;


        const [rows] = await db.promise().query(
            `SELECT COUNT(*) as count FROM notifications 
             WHERE email = ? AND is_read = 0`,
            [email]
        );

        const count = rows[0]?.count || 0;

        res.json({
            success: true,
            count: count
        });

    } catch (error) {
        console.error("Error fetching notification count:", error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch notification count"
        });
    }
});


app.get("/api/payment-summary", requireAdmin, async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];
        const thisMonth = new Date().getMonth() + 1;
        const thisYear = new Date().getFullYear();

        const queries = [

            db.promise().query(
                `SELECT COALESCE(SUM(amount_paid), 0) as today_total 
                 FROM payments 
                 WHERE DATE(payment_date) = ? AND status = 'Paid'`,
                [today]
            ),


            db.promise().query(
                `SELECT COALESCE(SUM(amount_paid), 0) as month_total 
                 FROM payments 
                 WHERE MONTH(payment_date) = ? AND YEAR(payment_date) = ? AND status = 'Paid'`,
                [thisMonth, thisYear]
            ),


            db.promise().query(
                `SELECT COUNT(*) as total_count FROM payments WHERE status = 'Paid'`
            ),


            db.promise().query(
                `SELECT COUNT(*) as pending_count FROM payments WHERE status = 'Pending'`
            )
        ];

        const results = await Promise.all(queries);

        res.json({
            success: true,
            summary: {
                today_total: parseFloat(results[0][0][0].today_total).toFixed(2),
                month_total: parseFloat(results[1][0][0].month_total).toFixed(2),
                total_count: results[2][0][0].total_count,
                pending_count: results[3][0][0].pending_count
            }
        });

    } catch (error) {
        console.error('Error fetching payment summary:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch payment summary'
        });
    }
});




app.get("/api/profit-statistics", requireAdmin, async (req, res) => {
    try {

        const query = `
            SELECT 
                DATE(p.payment_date) as date,
                COALESCE(SUM(p.amount_paid), 0) as profit
            FROM payments p
            WHERE p.status = 'Paid'
            GROUP BY DATE(p.payment_date)
            ORDER BY date DESC
            LIMIT 7
        `;

        const [profitData] = await db.promise().query(query);


        const today = new Date();
        const last7Days = [];


        for (let i = 6; i >= 0; i--) {
            const date = new Date(today);
            date.setDate(date.getDate() - i);
            const dateStr = date.toISOString().split('T')[0];


            const dayProfit = profitData
                .filter(item => item.date.toISOString().split('T')[0] === dateStr)
                .reduce((sum, item) => sum + parseFloat(item.profit), 0);

            last7Days.push({
                date: dateStr,
                profit: dayProfit
            });
        }

        res.json({
            success: true,
            data: {
                chartData: last7Days
            }
        });

    } catch (error) {
        console.error('Error fetching profit statistics:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch profit data'
        });
    }
});



app.get("/api/dashboard-stats", requireAdmin, async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];

        const queries = [

            db.promise().query(
                `SELECT COALESCE(SUM(amount_paid), 0) as today_revenue 
                 FROM payments 
                 WHERE DATE(payment_date) = ? AND status = 'Paid'`,
                [today]
            ),


            db.promise().query(
                `SELECT 
                    COUNT(*) as active_bookings_count,
                    SUM(
                        CASE 
                            WHEN no_of_rooms IS NULL OR no_of_rooms = '' THEN 1
                            ELSE CAST(no_of_rooms AS UNSIGNED)
                        END
                    ) as total_rooms_booked
                 FROM reservationsdetails 
                 WHERE status IN ('Pending', 'Permitted') 
                 AND check_in >= CURDATE()`
            ),


            db.promise().query(
                `SELECT COUNT(*) as total_rooms FROM rooms`
            ),


            db.promise().query(
                `SELECT 
                    COUNT(DISTINCT room_tag_split) as booked_rooms_count
                 FROM (
                     SELECT 
                         TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(r.roomTag, ',', n.n), ',', -1)) as room_tag_split
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
            )
        ];

        const results = await Promise.all(queries);

        const todayRevenue = parseFloat(results[0][0][0].today_revenue);
        const activeBookings = results[1][0][0].active_bookings_count;
        const totalRoomsBooked = results[1][0][0].total_rooms_booked || activeBookings;
        const totalRooms = results[2][0][0].total_rooms;
        const bookedRooms = results[3][0][0].booked_rooms_count || 0;
        const availableRooms = totalRooms - bookedRooms;
        const occupancyRate = totalRooms > 0 ? Math.round((bookedRooms / totalRooms) * 100) : 0;

        res.json({
            success: true,
            stats: {
                today_revenue: todayRevenue,
                active_bookings: totalRoomsBooked,
                total_bookings: activeBookings,
                available_rooms: availableRooms,
                occupancy_rate: occupancyRate,
                total_rooms: totalRooms,
                booked_rooms: bookedRooms
            }
        });

    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch dashboard statistics'
        });
    }
});


app.get("/api/revenue-weekly", requireAdmin, async (req, res) => {
    try {

        const query = `
            SELECT 
                DATE(payment_date) as date,
                DAYNAME(payment_date) as day,
                COALESCE(SUM(amount_paid), 0) as revenue
            FROM payments 
            WHERE payment_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            AND status = 'Paid'
            GROUP BY DATE(payment_date), DAYNAME(payment_date)
            ORDER BY date
        `;

        const [results] = await db.promise().query(query);

        const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
        const revenueData = {};


        days.forEach(day => {
            revenueData[day] = 0;
        });


        results.forEach(item => {
            const dayName = item.day.substring(0, 3);
            if (days.includes(dayName)) {
                revenueData[dayName] = parseFloat(item.revenue);
            }
        });


        const chartData = days.map(day => revenueData[day]);

        res.json({
            success: true,
            labels: days,
            data: chartData,
            rawData: results
        });

    } catch (error) {
        console.error('Error fetching weekly revenue:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch revenue data'
        });
    }
});


app.get("/api/room-distribution", requireAdmin, async (req, res) => {
    try {
        const query = `
            SELECT 
                r.room_type,
                SUM(
                    CASE 
                        WHEN r.no_of_rooms IS NULL OR r.no_of_rooms = '' THEN 1
                        ELSE CAST(r.no_of_rooms AS UNSIGNED)
                    END
                ) as total_rooms
            FROM reservationsdetails r
            WHERE r.status IN ('Permitted', 'Pending')
            AND r.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY r.room_type
            ORDER BY r.room_type
        `;

        const [results] = await db.promise().query(query);

        const roomTypeMap = {
            '5000': 'Standard',
            '7500': 'Deluxe',
            '12000': 'Suite',
            '18000': 'Family Suite'
        };

        const labels = [];
        const data = [];
        const backgroundColor = ['rgb(52, 152, 219)', 'rgb(39, 174, 96)', 'rgb(243, 156, 18)', 'rgb(155, 89, 182)'];

        results.forEach((item, index) => {
            const roomType = roomTypeMap[item.room_type] || `Type ${item.room_type}`;
            labels.push(roomType);
            data.push(item.total_rooms || 0);
        });

        if (labels.length === 0) {
            labels.push(...Object.values(roomTypeMap));
            data.push(...[10, 10, 10, 10]);
        }

        res.json({
            success: true,
            labels: labels,
            data: data,
            backgroundColor: backgroundColor.slice(0, labels.length),
            rawData: results,
            note: "Data shows total rooms (accounts for multiple rooms per booking)"
        });

    } catch (error) {
        console.error('Error fetching room distribution:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch room distribution data'
        });
    }
});


app.get("/api/dashboard/recent-bookings", requireAdmin, async (req, res) => {
    try {
        const limit = req.query.limit || 5;

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
                r.roomTag,  -- Make sure this is included
                r.status,
                r.total_amount,
                r.created_at,
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
            LIMIT ?
        `;

        const [results] = await db.promise().query(query, [parseInt(limit)]);

        const bookings = results.map(booking => {
            const roomTypeMap = {
                '5000': 'Standard',
                '7500': 'Deluxe',
                '12000': 'Suite',
                '18000': 'Family Suite'
            };


            let roomCount = 1;
            if (booking.roomTag) {
                const rooms = booking.roomTag.split(',').map(r => r.trim()).filter(r => r);
                roomCount = rooms.length;
            }

            return {
                ...booking,
                room_type_label: roomTypeMap[booking.room_type] || `Room (${booking.room_type})`,
                guest_name: `${booking.first_name || ''} ${booking.last_name || ''}`.trim(),
                booking_date: booking.created_at,
                room_count: roomCount,
                rooms_display: booking.roomTag
            };
        });

        res.json({
            success: true,
            bookings: bookings
        });

    } catch (error) {
        console.error('Error fetching recent bookings:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch recent bookings'
        });
    }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));