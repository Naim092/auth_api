const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { pool } = require('./db');
const router = express.Router();

router.use(express.json());

// Secret key for JWT
const JWT_SECRET = 'secret';

// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(403);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Admin registration
router.post('/admin/register', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    pool.query('INSERT INTO users (username, password, role) VALUES (?, ?, "admin")', 
               [username, hashedPassword], (err, results) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') {
                return res.status(400).send('Username already exists');
            }
            throw err;
        }
        res.send('Admin registered successfully');
    });
});

// Admin login
router.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    pool.query('SELECT * FROM users WHERE username = ? AND role = "admin"', [username], async (err, results) => {
        if (err) throw err;
        if (results.length === 0) return res.status(400).send('Invalid credentials');

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid credentials');

        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
});

// User login (not admin)
router.post('/user/login', (req, res) => {
    const { username, password } = req.body;
    pool.query('SELECT * FROM users WHERE username = ? AND role = "user"', [username], async (err, results) => {
        if (err) throw err;
        if (results.length === 0) return res.status(400).send('Invalid credentials');

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid credentials');

        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Company login
router.post('/company/login', (req, res) => {
    const { username, password } = req.body;
    pool.query('SELECT * FROM companies WHERE username = ?', [username], async (err, results) => {
        if (err) throw err;
        if (results.length === 0) return res.status(400).send('Invalid credentials');

        const company = results[0];
        const isMatch = await bcrypt.compare(password, company.password);
        if (!isMatch) return res.status(400).send('Invalid credentials');

        const token = jwt.sign({ id: company.id, role: 'company' }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Register a new user (Admin only)
router.post('/admin/register-user', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);

    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    pool.query('INSERT INTO users (username, password, role) VALUES (?, ?, "user")', 
               [username, hashedPassword], (err, results) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') {
                return res.status(400).send('Username already exists');
            }
            throw err;
        }
        res.send('User registered successfully');
    });
});

// Register a new company (Admin only)
router.post('/admin/register-company', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);

    const { name, address, username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    pool.query('INSERT INTO companies (name, address, username, password) VALUES (?, ?, ?, ?)', 
               [name, address, username, hashedPassword], (err, results) => {
        if (err) throw err;
        res.send('Company registered successfully');
    });
});

// View companies (User and Admin)
router.get('/companies', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin' && req.user.role !== 'user') return res.sendStatus(403);

    pool.query('SELECT * FROM companies', (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

// Edit a company (Admin and Company)
router.put('/company/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { name, address, username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    if (req.user.role !== 'admin' && req.user.id != id) return res.sendStatus(403);

    pool.query('UPDATE companies SET name = ?, address = ?, username = ?, password = ? WHERE id = ?', 
               [name, address, username, hashedPassword, id], (err, results) => {
        if (err) throw err;
        res.send('Company details updated successfully');
    });
});

// Delete a company (Admin only)
router.delete('/company/:id', authenticateToken, (req, res) => {
    const { id } = req.params;

    if (req.user.role !== 'admin') return res.sendStatus(403);

    pool.query('DELETE FROM companies WHERE id = ?', [id], (err, results) => {
        if (err) throw err;
        res.send('Company deleted successfully');
    });
});

module.exports = router;
