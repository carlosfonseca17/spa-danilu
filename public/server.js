const bcrypt = require('bcrypt');
const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const app = express();

// Configurar conexión a la base de datos
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'danilu'
});

db.connect(error => {
    if (error) throw error;
    console.log('Conectado a la base de datos MySQL');
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// 🧾 RUTA: Registrar cliente con contraseña encriptada
app.post('/api/clientes', (req, res) => {
    const { id_cliente, nombre, correo, telefono, contrasena } = req.body;

    bcrypt.hash(contrasena, 10, (err, hash) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Error al encriptar la contraseña' });
        }

        const query = 'INSERT INTO clientes (id_cli, nom_cli, corr_cli, nume_clie, cont_clie) VALUES (?, ?, ?, ?, ?)';
        db.query(query, [id_cliente, nombre, correo, telefono, hash], (error, results) => {
            if (error) {
                console.error('Error al registrar cliente:', error);
                res.status(500).json({ success: false, message: 'Error al registrar cliente' });
            } else {
                res.json({ success: true, message: 'Cliente registrado correctamente' });
            }
        });
    });
});

// 🔐 RUTA: Login comparando contraseña encriptada
app.post('/api/login', (req, res) => {
    const { correo, contrasena } = req.body;

    const query = 'SELECT * FROM clientes WHERE corr_cli = ?';
    db.query(query, [correo], (error, results) => {
        if (error) {
            return res.status(500).json({ success: false, message: 'Error en el servidor' });
        }

        if (results.length > 0) {
            const user = results[0];

            bcrypt.compare(contrasena, user.cont_clie, (err, isMatch) => {
                if (err || !isMatch) {
                    return res.json({ success: false, message: 'Correo o contraseña incorrectos' });
                }

                res.json({ success: true, user });
            });
        } else {
            res.json({ success: false, message: 'Correo o contraseña incorrectos' });
        }
    });
});

// 🔍 RUTA: Verificar si existe cliente
app.get('/api/clientes/existe/:valor', (req, res) => {
    const valor = req.params.valor;

    const query = 'SELECT * FROM clientes WHERE id_cli = ? OR corr_cli = ?';
    db.query(query, [valor, valor], (error, results) => {
        if (error) {
            res.status(500).json({ success: false, message: 'Error al verificar cliente' });
        } else {
            res.json({ existe: results.length > 0 });
        }
    });
});

// 📅 RUTA: Guardar reserva
app.post('/api/reservas', (req, res) => {
    const { id_rese, fec_rese, hor_rese, val_rese, id_clie } = req.body;

    const query = `INSERT INTO reservas (id_rese, fec_rese, hor_rese, val_rese, id_clie)
                   VALUES (?, ?, ?, ?, ?)`;

    db.query(query, [id_rese, fec_rese, hor_rese, val_rese, id_clie], (error, results) => {
        if (error) {
            console.error('Error al guardar reserva:', error);
            res.status(500).json({ success: false, message: 'Error al guardar la reserva' });
        } else {
            res.json({ success: true, message: 'Reserva guardada exitosamente' });
        }
    });
});

// 🟢 Servidor
app.listen(3000, () => {
    console.log('Servidor corriendo en http://localhost:3000');
});

