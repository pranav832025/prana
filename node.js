const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;

// PostgreSQL connection pool
const pool = new Pool({
    user: 'your_username',
    host: 'localhost',
    database: 'participants_db',
    password: 'your_password',
    port: 5432,
});

// Middleware to parse JSON
app.use(bodyParser.json());

// Secret key for JWT
const JWT_SECRET = 'your_secret_key';

// Endpoint for user registration (sign-up)
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (username, password) VALUES ($1, $2)',
            [username, hashedPassword]
        );
        res.status(201).send('User registered successfully');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// Endpoint for user login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
                res.json({ token });
            } else {
                res.status(400).send('Invalid credentials');
            }
        } else {
            res.status(400).send('User not found');
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).send('Token required');
    }
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send('Invalid token');
        }
        req.user = decoded;
        next();
    });
};

// Endpoint to get quiz questions (for a specific round)
app.get('/api/questions/:round', verifyToken, async (req, res) => {
    const { round } = req.params;
    try {
        const result = await pool.query('SELECT * FROM questions WHERE round = $1', [round]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// Endpoint to submit quiz scores
app.post('/api/submitQuiz', verifyToken, async (req, res) => {
    const { score, round } = req.body;
    const userId = req.user.userId;
    try {
        await pool.query(
            'INSERT INTO participants (user_id, score, round) VALUES ($1, $2, $3)',
            [userId, score, round]
        );
        res.status(200).send('Score submitted successfully');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
