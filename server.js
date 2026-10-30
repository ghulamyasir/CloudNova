
require("dotenv").config();

const express = require("express");
const path = require("path");
const db = require("./db");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Authentication middleware
function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect("/login.html");
    }
    next();
}

// Admin authorization middleware
function requireAdmin(req, res, next) {
    if (!req.session.user || req.session.user.role !== "admin") {
        return res.redirect("/login.html");
    }
    next();
}

// Home page
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Protected dashboard pages
app.get("/user-dashboard.html", requireAuth, (req, res) => {
    if (req.session.user.role !== "user") {
        return res.redirect("/admin-dashboard.html");
    }

    res.sendFile(path.join(__dirname, "public", "user-dashboard.html"));
});

app.get("/admin-dashboard.html", requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin-dashboard.html"));
});

// Current logged-in user API
app.get("/api/me", requireAuth, (req, res) => {
    res.json({
        success: true,
        user: req.session.user
    });
});

// Logout API
app.post("/api/logout", (req, res) => {
    if (!req.session) {
        return res.json({
            success: true,
            message: "Logged out successfully."
        });
    }

    req.session.destroy((error) => {
        if (error) {
            console.error("Logout error:", error.message);

            return res.status(500).json({
                success: false,
                message: "Could not log out."
            });
        }

        res.clearCookie("connect.sid");

        res.json({
            success: true,
            message: "Logged out successfully."
        });
    });
});

// Test MySQL connection
app.get("/api/db-test", async (req, res) => {
    let connection;

    try {
        connection = await db.getConnection();
        await connection.query("SELECT 1");

        res.json({
            success: true,
            message: "CloudNova successfully connected to MySQL database!"
        });
    } catch (error) {
        console.error("Database connection error:", error.message);

        res.status(500).json({
            success: false,
            message: "Database connection failed."
        });
    } finally {
        if (connection) connection.release();
    }
});

// User Registration API
app.post("/api/register", async (req, res) => {
    try {
        const { fullName, email, password, confirmPassword } = req.body;

        if (!fullName || !email || !password || !confirmPassword) {
            return res.status(400).json({
                success: false,
                message: "Please fill in all required fields."
            });
        }

        if (fullName.trim().length < 3) {
            return res.status(400).json({
                success: false,
                message: "Full name must contain at least 3 characters."
            });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: "Please enter a valid email address."
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: "Password must contain at least 8 characters."
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: "Passwords do not match."
            });
        }

        const [existingUsers] = await db.execute(
            "SELECT id FROM users WHERE email = ?",
            [email.trim().toLowerCase()]
        );

        if (existingUsers.length > 0) {
            return res.status(409).json({
                success: false,
                message: "This email is already registered."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        await db.execute(
            "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
            [
                fullName.trim(),
                email.trim().toLowerCase(),
                hashedPassword,
                "user"
            ]
        );

        res.status(201).json({
            success: true,
            message: "Account created successfully! You can now sign in."
        });

    } catch (error) {
        console.error("Registration error:", error.message);

        res.status(500).json({
            success: false,
            message: "Registration failed. Please try again."
        });
    }
});

// User Login API
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Please enter your email and password."
            });
        }

        const [users] = await db.execute(
            "SELECT id, name, email, password, role FROM users WHERE email = ?",
            [email.trim().toLowerCase()]
        );

        if (users.length === 0) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        const user = users[0];

        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        req.session.regenerate((error) => {
            if (error) {
                console.error("Session error:", error.message);

                return res.status(500).json({
                    success: false,
                    message: "Could not create login session."
                });
            }

            req.session.user = {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            };

            req.session.save((saveError) => {
                if (saveError) {
                    console.error("Session save error:", saveError.message);

                    return res.status(500).json({
                        success: false,
                        message: "Could not save login session."
                    });
                }

                res.json({
                    success: true,
                    message: "Login successful!",
                    redirect: user.role === "admin"
                        ? "admin-dashboard.html"
                        : "user-dashboard.html"
                });
            });
        });

    } catch (error) {
        console.error("Login error:", error.message);

        res.status(500).json({
            success: false,
            message: "Login failed. Please try again."
        });
    }
});

// Backend status
app.get("/api/status", (req, res) => {
    res.json({
        success: true,
        message: "CloudNova backend is running successfully!",
        platform: "Node.js + Express"
    });
});

// Serve other frontend files.
// Keep this AFTER protected dashboard routes.
app.use(express.static(path.join(__dirname, "public")));

// Start server
app.listen(PORT, () => {
    console.log(`CloudNova server running at http://localhost:${PORT}`);
});