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
        const { name, kategori, email, password, role } = req.body;
        console.log("DATA CREATE USER =", req.body);
        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await db.query(
            "INSERT INTO users (name,kategori,email,password,role) VALUES (?,?,?,?,?)",
            [name, kategori, email, hashedPassword, role]
        );

        console.log("INSERT RESULT =", result);
        console.log("KATEGORI YANG DISIMPAN =", kategori);

        await logActivity(
            req.user.id,
            req.user.name,
            req.user.email,
            "CREATE",
            `Menambahkan user ${name} (${email})`
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
        const { name, kategori,email, password, role } = req.body;

        let hashedPassword = password;

        if (password && !password.startsWith("$2")) {
            hashedPassword = await bcrypt.hash(password, 10);
        }
        await db.query(
            "UPDATE users SET name=?, kategori=?,email=?, password=?, role=? WHERE id=?",
            [name, kategori, email, hashedPassword, role, id]
        );



        await logActivity(
            req.user.id,
            req.user.name,
            req.user.email,
            "UPDATE",
            `Mengubah user ${name} (${email}) menjadi role ${role}`
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

        await logActivity(
            req.user.id,
            req.user.name,
            req.user.email,
            "CHANGE_PASSWORD",
            `${req.user.email} berhasil mengubah password`
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
// ==================== ACTIVITY LOG ====================



async function logActivity(
    userId,
    name,
    email,
    action,
    description,
    transactionCode = null
) {
    try {

        console.log("LOG ACTIVITY:", {
            userId,
            name,
            email,
            action,
            description,
            transactionCode,
        });

        await db.query(
            "INSERT INTO activity_logs (user_id,name,email,action,transaction_code,description) VALUES (?,?,?,?,?,?)",
            [userId, name, email, action, transactionCode, description]
        );

        console.log("Activity berhasil disimpan");

    } catch (err) {
        console.error("Activity Log Error:", err);
    }
}

// ==================== DELETE ====================

app.delete("/api/v1/users/:id", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        // Ambil data user sebelum dihapus
        const [rows] = await db.query(
            "SELECT name, email FROM users WHERE id=?",
            [id]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                message: "User tidak ditemukan",
            });
        }

        const deletedUser = rows[0];

        // Hapus user
        await db.query(
            "DELETE FROM users WHERE id=?",
            [id]
        );

        // Simpan activity log
        await logActivity(
            req.user.id,
            req.user.name,
            req.user.email,
            "DELETE",
            `Menghapus user ${deletedUser.name} (${deletedUser.email})`
        );

        res.json({
            message: "User berhasil dihapus",
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            message: err.message,
        });
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
                name: user.name,
                email: user.email,
                role: user.role,
            },


            JWT_SECRET,
            {
                expiresIn: "1d",
            }
        );

        await logActivity(
            user.id,
            user.name,
            user.email,
            "LOGIN",
            `${user.email} berhasil login`
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
// ==================== LOGOUT ====================

app.post("/api/v1/logout", verifyToken, async (req, res) => {
    try {

        await logActivity(
            req.user.id,
            req.user.name,
            req.user.email,
            "LOGOUT",
            `${req.user.email} berhasil logout`
        );

        res.json({
            message: "Logout berhasil",
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: err.message,
        });
    }
});

// ==================== GET ACTIVITY LOG ====================

app.get("/api/v1/activity-logs", verifyToken, verifyAdmin, async (req, res) => {
    try {

        const [rows] = await db.query(`
            SELECT *
            FROM activity_logs
            ORDER BY created_at DESC
        `);

        res.json(rows);

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: err.message,
        });
    }
});
// ==================== GET PRODUCTS ====================

app.get("/api/v1/products", verifyToken, async (req, res) => {
    try {

        const [rows] = await db.query(`
            SELECT
                p.id,
                p.category_id,
                c.name AS category_name,
                p.code,
                p.name,
                p.purchase_price,
                p.selling_price,
                p.stock,
                p.unit,
                p.is_active,
                p.created_at,
                p.updated_at
            FROM products p
            INNER JOIN categories c
                ON p.category_id = c.id
            ORDER BY p.id DESC
        `);

        res.json(rows);

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: err.message,
        });
    }
});


// ==================== CREATE PRODUCT ====================

app.post("/api/v1/products", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const {
            category_id,
            code,
            name,
            purchase_price,
            selling_price,
            stock,
            unit
        } = req.body;

        if (!category_id || !code || !name) {
            return res.status(400).json({
                message: "category_id, code, dan name wajib diisi"
            });
        }

        const [result] = await db.query(
            `
            INSERT INTO products
            (
                category_id,
                code,
                name,
                purchase_price,
                selling_price,
                stock,
                unit
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            `,
            [
                category_id,
                code,
                name,
                purchase_price || 0,
                selling_price || 0,
                stock || 0,
                unit || "pcs"
            ]
        );

        res.status(201).json({
            message: "Produk berhasil ditambahkan",
            productId: result.insertId
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: err.message
        });
    }
});

// ==================== UPDATE PRODUCT ====================

app.put("/api/v1/products/:id", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        const {
            category_id,
            code,
            name,
            purchase_price,
            selling_price,
            stock,
            unit,
            is_active
        } = req.body;

        if (!category_id || !code || !name) {
            return res.status(400).json({
                message: "category_id, code, dan name wajib diisi"
            });
        }

        const [result] = await db.query(
            `
            UPDATE products
            SET
                category_id = ?,
                code = ?,
                name = ?,
                purchase_price = ?,
                selling_price = ?,
                stock = ?,
                unit = ?,
                is_active = ?
            WHERE id = ?
            `,
            [
                category_id,
                code,
                name,
                purchase_price ?? 0,
                selling_price ?? 0,
                stock ?? 0,
                unit || "pcs",
                is_active ?? 1,
                id
            ]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                message: "Produk tidak ditemukan"
            });
        }

        res.json({
            message: "Produk berhasil diperbarui"
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: err.message
        });
    }
});

// ==================== DELETE PRODUCT ====================

app.delete("/api/v1/products/:id", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        const [result] = await db.query(
            `
            UPDATE products
            SET is_active = 0
            WHERE id = ?
            `,
            [id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                message: "Produk tidak ditemukan"
            });
        }

        res.json({
            message: "Produk berhasil dinonaktifkan"
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: err.message
        });
    }
});

// ==================== GET BEST SELLING PRODUCTS ====================

app.get("/api/v1/products/best-selling", verifyToken, async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT
                p.id AS product_id,
                p.code,
                p.name AS product_name,
                p.unit,

                SUM(ti.quantity) AS total_quantity,

                SUM(ti.subtotal) AS total_sales,

                SUM(
                    ti.quantity * ti.cost_price
                ) AS total_hpp,

                SUM(
                    ti.subtotal -
                    (ti.quantity * ti.cost_price)
                ) AS gross_profit

            FROM transaction_items ti

            INNER JOIN products p
                ON p.id = ti.product_id

            GROUP BY
                p.id,
                p.code,
                p.name,
                p.unit

            ORDER BY total_quantity DESC

            LIMIT 10
        `);

        res.json(rows);

    } catch (err) {
        console.error("BEST SELLING ERROR:", err);

        res.status(500).json({
            message: err.message
        });
    }
});



// ==================== GET CATEGORIES ====================

app.get("/api/v1/categories", verifyToken, async (req, res) => {
    try {

        const [rows] = await db.query(`
    SELECT
        id,
        name,
        created_at
    FROM categories
    WHERE is_active = 1
    ORDER BY name ASC
`);

        res.json(rows);

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: err.message
        });
    }
});


// ==================== CREATE CATEGORY ====================

app.post("/api/v1/categories", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { name } = req.body;

        if (!name || !name.trim()) {
            return res.status(400).json({
                message: "Nama kategori wajib diisi"
            });
        }

        const [result] = await db.query(
            `
            INSERT INTO categories (name)
            VALUES (?)
            `,
            [name.trim()]
        );

        res.status(201).json({
            message: "Kategori berhasil ditambahkan",
            categoryId: result.insertId
        });

    } catch (err) {
        console.error(err);

        if (err.code === "ER_DUP_ENTRY") {
            return res.status(409).json({
                message: "Kategori sudah ada"
            });
        }

        res.status(500).json({
            message: err.message
        });
    }
});

// ==================== UPDATE CATEGORY ====================

app.put("/api/v1/categories/:id", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { name } = req.body;

        if (!name || !name.trim()) {
            return res.status(400).json({
                message: "Nama kategori wajib diisi"
            });
        }

        const [result] = await db.query(
            `
            UPDATE categories
            SET name = ?
            WHERE id = ?
            `,
            [name.trim(), id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                message: "Kategori tidak ditemukan"
            });
        }

        res.json({
            message: "Kategori berhasil diperbarui"
        });

    } catch (err) {
        console.error(err);

        if (err.code === "ER_DUP_ENTRY") {
            return res.status(409).json({
                message: "Kategori sudah ada"
            });
        }

        res.status(500).json({
            message: err.message
        });
    }
});

// ==================== UPDATE CATEGORY ====================

app.put("/api/v1/categories/:id", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { name } = req.body;

        if (!name || !name.trim()) {
            return res.status(400).json({
                message: "Nama kategori wajib diisi"
            });
        }

        const [result] = await db.query(
            `
            UPDATE categories
            SET name = ?
            WHERE id = ?
            `,
            [name.trim(), id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                message: "Kategori tidak ditemukan"
            });
        }

        res.json({
            message: "Kategori berhasil diperbarui"
        });

    } catch (err) {
        console.error(err);

        if (err.code === "ER_DUP_ENTRY") {
            return res.status(409).json({
                message: "Kategori sudah ada"
            });
        }

        res.status(500).json({
            message: err.message
        });
    }
});

// ==================== DELETE CATEGORY ====================

app.delete("/api/v1/categories/:id", verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        const [result] = await db.query(
            `
            UPDATE categories
            SET is_active = 0
            WHERE id = ?
            `,
            [id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                message: "Kategori tidak ditemukan"
            });
        }

        res.json({
            message: "Kategori berhasil dinonaktifkan"
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: err.message
        });
    }
});


// ==================== CREATE TRANSACTION ====================

app.post("/api/v1/transactions", verifyToken, async (req, res) => {

    console.log("=== POST TRANSACTIONS MASUK ===");
    console.log("BODY TRANSAKSI =", req.body);
    console.log("USER =", req.user);
    console.log("=== SEBELUM GET CONNECTION ===");
    const connection = await db.getConnection();
    console.log("=== GET CONNECTION BERHASIL ===");

    try {
        const {
            items,
            discount = 0,
            paid_amount,
            payment_method = "cash"
        } = req.body;


        const allowedPaymentMethods = [
            "cash",
            "debit",
            "qris",
            "transfer"
        ];

        if (!allowedPaymentMethods.includes(payment_method)) {
            return res.status(400).json({
                message: "Metode pembayaran tidak valid"
            });
        }
        // ==================== VALIDASI ====================

        if (!Array.isArray(items) || items.length === 0) {
            return res.status(400).json({
                message: "Minimal satu produk harus dipilih"
            });
        }

        if (paid_amount === undefined || paid_amount === null) {
            return res.status(400).json({
                message: "Jumlah pembayaran wajib diisi"
            });
        }

        if (Number(discount) < 0) {
            return res.status(400).json({
                message: "Diskon tidak boleh negatif"
            });
        }

        // ==================== START TRANSACTION ====================

        console.log("=== SEBELUM BEGIN TRANSACTION ===");
        await connection.beginTransaction();
        console.log("=== BEGIN TRANSACTION BERHASIL ===");

        let subtotal = 0;
        const transactionItems = [];

        // ==================== CEK PRODUK & STOK ====================

        for (const item of items) {
            const productId = Number(item.product_id);
            const quantity = Number(item.quantity);

            if (!Number.isInteger(productId) || quantity <= 0) {
                throw new Error("Product ID atau quantity tidak valid");
            }

            const [products] = await connection.query(
                `
                SELECT
                    id,
                    name,
                    purchase_price,
                    selling_price,
                    stock,
                    is_active
                FROM products
                WHERE id = ?
                FOR UPDATE
                `,
                [productId]
            );

            if (products.length === 0) {
                throw new Error(`Produk ID ${productId} tidak ditemukan`);
            }

            const product = products[0];

            if (product.is_active !== 1) {
                throw new Error(`Produk ${product.name} tidak aktif`);
            }

            if (Number(product.stock) < quantity) {
                throw new Error(
                    `Stok ${product.name} tidak cukup. Stok tersedia: ${product.stock}`
                );
            }

            const price = Number(product.selling_price);
            const itemSubtotal = price * quantity;

            subtotal += itemSubtotal;
            transactionItems.push({
                product_id: product.id,
                quantity,
                price,
                cost_price: Number(product.purchase_price),
                subtotal: itemSubtotal
            });
        }

        // ==================== HITUNG TOTAL ====================

        const discountAmount = Number(discount);
        const grandTotal = subtotal - discountAmount;
        if (grandTotal < 0) {
            throw new Error("Diskon tidak boleh lebih besar dari subtotal");
        }

        const paidAmount = Number(paid_amount);

        if (paidAmount < grandTotal) {
            throw new Error("Pembayaran kurang");
        }

        const changeAmount = paidAmount - grandTotal;

        // ==================== GENERATE CODE ====================

        const transactionCode =
            "TRX-" +
            Date.now() +
            "-" +
            Math.floor(Math.random() * 1000);

        // ==================== INSERT TRANSACTION ====================





        const [transactionResult] = await connection.query(
            `
    INSERT INTO transactions
    (
        transaction_code,
        user_id,
        subtotal,
        discount,
        grand_total,
        paid_amount,
        change_amount,
        payment_method
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
            [
                transactionCode,
                req.user.id,
                subtotal,
                discountAmount,
                grandTotal,
                paidAmount,
                changeAmount,
                payment_method
            ]
        );



        const transactionId = transactionResult.insertId;

        // ==================== INSERT ITEMS & KURANGI STOK ====================

        for (const item of transactionItems) {
            await connection.query(
                `
                INSERT INTO transaction_items
                (
                    transaction_id,
                    product_id,
                    quantity,
                    price,
                    cost_price,
                    subtotal
                )
                VALUES (?, ?, ?, ?, ?, ?)
                `,
                [
                    transactionId,
                    item.product_id,
                    item.quantity,
                    item.price,
                    item.cost_price,
                    item.subtotal
                ]
            );

            await connection.query(
                `
                UPDATE products
                SET stock = stock - ?
                WHERE id = ?
                `,
                [
                    item.quantity,
                    item.product_id
                ]
            );
        }

        // ==================== COMMIT ====================
        console.log("=== SEBELUM COMMIT ===");
        await connection.commit();
        console.log("=== COMMIT BERHASIL ===");

        await logActivity(
            req.user.id,
            req.user.name,
            req.user.email,
            "CREATE",
            `Membuat transaksi ${transactionCode} dengan total Rp${grandTotal.toLocaleString("id-ID")}`,
            transactionCode
        );

        res.status(201).json({
            message: "Transaksi berhasil",
            transactionId,
            transactionCode,
            subtotal,
            discount: discountAmount,
            grand_total: grandTotal,
            paid_amount: paidAmount,
            change_amount: changeAmount,
            payment_method: payment_method
        });

    } catch (err) {

        await connection.rollback();

        console.error(err);

        res.status(400).json({
            message: err.message
        });

    } finally {
        connection.release();
    }
});




// ==================== GET TRANSACTIONS ====================
app.get("/api/v1/transactions", verifyToken, async (req, res) => {
    try {

        const [rows] = await db.query(`
    SELECT
        t.id,
        t.transaction_code,
        t.user_id,
        u.name AS cashier_name,
        u.email AS cashier_email,
        t.subtotal,
        t.discount,
        t.grand_total,
        t.paid_amount,
        t.change_amount,
        t.payment_method,
        t.created_at,

        COALESCE(
            (
                SELECT SUM(
                    ti.quantity * ti.cost_price
                )
                FROM transaction_items ti
                WHERE ti.transaction_id = t.id
            ),
            0
        ) AS total_hpp,

        (
            t.grand_total -
            COALESCE(
                (
                    SELECT SUM(
                        ti.quantity * ti.cost_price
                    )
                    FROM transaction_items ti
                    WHERE ti.transaction_id = t.id
                ),
                0
            )
        ) AS gross_profit

    FROM transactions t
    INNER JOIN users u
        ON t.user_id = u.id
    ORDER BY t.created_at DESC

`);

        res.json(rows);
    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: err.message
        });
    }
});

// ==================== GET TRANSACTION DETAIL ====================

app.get("/api/v1/transactions/:id", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        // ==================== GET TRANSACTION ====================

        const [transactions] = await db.query(
            `
            SELECT
                t.id,
                t.transaction_code,
                t.user_id,
                u.name AS cashier_name,
                u.email AS cashier_email,
                t.subtotal,
                t.discount,
                t.grand_total,
                t.paid_amount,
                t.change_amount,
                t.payment_method,
                t.created_at
            FROM transactions t
            INNER JOIN users u
                ON t.user_id = u.id
            WHERE t.id = ?
            `,
            [id]
        );

        if (transactions.length === 0) {
            return res.status(404).json({
                message: "Transaksi tidak ditemukan"
            });
        }

        // ==================== GET ITEMS ====================

        const [items] = await db.query(
            `
    SELECT
        ti.id,
        ti.product_id,
        p.code AS product_code,
        p.name AS product_name,
        ti.quantity,
        ti.price,
        ti.cost_price,
        ti.subtotal,
        (
            ti.subtotal -
            (ti.quantity * ti.cost_price)
        ) AS item_profit,
        p.unit
    FROM transaction_items ti
    INNER JOIN products p
        ON ti.product_id = p.id
    WHERE ti.transaction_id = ?
    ORDER BY ti.id ASC
    `,
            [id]
        );

        res.json({
            transaction: transactions[0],
            items
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: err.message
        });
    }
});


app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});


