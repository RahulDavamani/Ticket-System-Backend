const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const SECRET_KEY = "your_secret_key"; // Use a secure key in production

app.use(bodyParser.json());
app.use(cors());

const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            firstName TEXT,
            lastName TEXT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT
        )`, (err) => {
            if (err) {
                console.error('Error creating users table:', err.message);
            } else {
                console.log('Users table created or already exists.');
            }
        });

        db.run(`CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT,
            title TEXT,
            description TEXT,
            status TEXT DEFAULT 'Open',
            priority TEXT
        )`, (err) => {
            if (err) {
                console.error('Error creating tickets table:', err.message);
            } else {
                console.log('Tickets table created or already exists.');
            }
        });
    }
});

// Middleware for verifying JWT tokens
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).send({ auth: false, message: 'No token provided.' });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
        req.userId = decoded.id;
        next();
    });
};

// User Registration
app.post('/register', (req, res) => {
    const { firstName, lastName, username, email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);

    const sql = `INSERT INTO users (firstName, lastName, username, email, password) VALUES (?, ?, ?, ?, ?)`;
    const params = [firstName, lastName, username, email, hashedPassword];

    db.run(sql, params, function (err) {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
        res.json({ message: 'User registered successfully' });
    });
});

// User Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const sql = `SELECT * FROM users WHERE username = ?`;

    db.get(sql, [username], (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: 86400 }); // 24 hours
        res.json({ auth: true, token, user });
    });
});

// Create Ticket
app.post('/tickets', (req, res) => {
    const { category, title, description, status, priority } = req.body;

    const sql = `INSERT INTO tickets (category, title, description, status, priority) VALUES (?, ?, ?, 'Open', ?)`;
    const params = [category, title, description, priority];

    db.run(sql, params, function (err) {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
        res.json({ message: 'Ticket created successfully', ticketId: this.lastID });
    });
});

// Fetch Tickets
app.get('/tickets', (req, res) => {
    const sql = `SELECT * FROM tickets`;
    db.all(sql, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

// Fetch Tickets with optional category filtering
app.get('/tickets', (req, res) => {
    const { category } = req.query;
    let sql = `SELECT * FROM tickets`; 
    const params = [];

    if (category) {
        sql += ` WHERE category = ?`;
        params.push(category);
    }

    db.all(sql, params, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});


app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
