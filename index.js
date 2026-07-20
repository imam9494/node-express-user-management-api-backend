require("dotenv").config();




const verifyToken = require("./middleware/verifyToken");
const verifyAdmin = require("./middleware/verifyAdmin");




require("dotenv").config();


const db = require("./db");






const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");


const app = express();

const JWT_SECRET = "imam123456";

app.use(cors());
app.use(express.json());



// ==================== GET ====================

app.get("/api/v1/users", verifyToken, async (req, res) => {
    try {
        const [rows] = await db.query("SELECT * FROM users");
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

// ==================== POST ====================

app.post("/api/v1/users", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        const hashedPassword = await bcrypt.hash(password, 10);

        await db.query(
            "INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)",
            [name, email, hashedPassword, role]
        );

        res.json({
            message: "User berhasil ditambahkan",
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: err.message,
            code: err.code,
        });
    }
});

// ==================== PUT ====================
app.put("/api/v1/users/:id", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, email, password, role } = req.body;

        let hashedPassword = password;

        if (password && !password.startsWith("$2")) {
            hashedPassword = await bcrypt.hash(password, 10);
        }

        await db.query(
            "UPDATE users SET name=?, email=?, password=?, role=? WHERE id=?",
            [name, email, hashedPassword, role, id]
        );

        res.json({
            message: "User berhasil diupdate",
        });

    } catch (err) {
        console.error(err);
        res.status(500).json(err);
    }
});


// ==================== CHANGE PASSWORD ====================

app.put("/api/v1/change-password", verifyToken, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;

        if (!oldPassword || !newPassword) {
            return res.status(400).json({
                message: "Password lama dan password baru harus diisi",
            });
        }

        const [rows] = await db.query(
            "SELECT password FROM users WHERE id=?",
            [req.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                message: "User tidak ditemukan",
            });
        }

        const cocok = await bcrypt.compare(
            oldPassword,
            rows[0].password
        );

        if (!cocok) {
            return res.status(400).json({
                message: "Password lama salah",
            });
        }

        const hash = await bcrypt.hash(newPassword, 10);

        await db.query(
            "UPDATE users SET password=? WHERE id=?",
            [hash, req.user.id]
        );

        res.json({
            message: "Password berhasil diubah",
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: err.message,
        });
    }
});

// ==================== DELETE ====================

app.delete("/api/v1/users/:id", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        await db.query(
            "DELETE FROM users WHERE id=?",
            [id]
        );

        res.json({
            message: "User berhasil dihapus",
        });

    } catch (err) {
        console.error(err);
        res.status(500).json(err);
    }
});

// ==================== LOGIN ====================

app.post("/api/v1/login", async (req, res) => {
    try {

        const { email, password } = req.body;

        const [rows] = await db.query(
            "SELECT * FROM users WHERE email=?",
            [email]
        );

        if (rows.length === 0) {
            return res.status(401).json({
                message: "Email atau password salah",
            });
        }

        const user = rows[0];

        const cocok = await bcrypt.compare(
            password,
            user.password
        );

        if (!cocok) {
            return res.status(401).json({
                message: "Email atau password salah",
            });
        }

        const token = jwt.sign(
            {
                id: user.id,
                email: user.email,
                role: user.role,
            },
            JWT_SECRET,
            {
                expiresIn: "1d",
            }
        );

        res.json({
            message: "Login berhasil",
            token,
            user,
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: err.message,
        });
    }
});

app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});