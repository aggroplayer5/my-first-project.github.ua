const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;
const db = new sqlite3.Database('./holy_shop.db');

app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user'
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product TEXT,
        deadline TEXT
    )`);

    const adminEmail = 'oboroznijsasa@gmail.com';
    const adminPlainPassword = 'admintralalatapolya';
    
    db.get("SELECT * FROM users WHERE email = ?", [adminEmail], (err, row) => {
        if (!row) {
            const salt = bcrypt.genSaltSync(10);
            const hashedPassword = bcrypt.hashSync(adminPlainPassword, salt);
            db.run("INSERT INTO users (email, password, role) VALUES (?, ?, 'admin')", [adminEmail, hashedPassword]);
            console.log('Администратор проинициализирован в БД.');
        }
    });
});

app.get('/api/check-auth', (req, res) => {
    const userEmail = req.cookies.user_email;
    const userRole = req.cookies.user_role;

    if (userEmail && userRole) {
        return res.json({ loggedIn: true, email: userEmail, role: userRole });
    }
    res.json({ loggedIn: false });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ success: false, message: 'Неверные данные' });
        }
        
        const cookieOptions = { 
            maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/',
            httpOnly: false
        };

        res.cookie('user_email', user.email, cookieOptions);
        res.cookie('user_role', user.role, cookieOptions);

        res.json({ success: true, role: user.role, email: user.email });
    });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('user_email', { path: '/' });
    res.clearCookie('user_role', { path: '/' });
    res.json({ success: true });
});

app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Заполните поля' });
    const hashedPassword = bcrypt.hashSync(password, bcrypt.genSaltSync(10));
    db.run("INSERT INTO users (email, password) VALUES (?, ?)", [email, hashedPassword], (err) => {
        if (err) return res.status(400).json({ success: false, message: 'Email занят' });
        res.json({ success: true, message: 'Регистрация успешна!' });
    });
});

app.get('/api/orders', (req, res) => {
    db.all("SELECT id, product, deadline FROM orders", [], (err, rows) => { 
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows); 
    });
});

app.post('/api/orders', (req, res) => {
    const { product, deadline } = req.body;
    db.run("INSERT INTO orders (product, deadline) VALUES (?, ?)", [product, deadline], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, product, deadline });
    });
});

app.delete('/api/orders/:id', (req, res) => {
    const orderId = req.params.id;
    db.run("DELETE FROM orders WHERE id = ?", [orderId], function(err) {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, message: 'Заказ успешно удален' });
    });
});

app.get('/', (req, res) => { 
    res.sendFile(path.join(__dirname, 'public', 'index.html')); 
});

app.listen(PORT, () => console.log(`Сервер успешно запущен на http://localhost:${PORT}`));