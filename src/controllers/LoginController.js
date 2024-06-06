const bcrypt = require('bcrypt');

// Controlador para la página de inicio de sesión
function login(req, res) {
    if (req.session.loggedin != true) {
        res.render('login/index');
    } else {
        res.redirect('/');
    }
}

// Controlador para autenticar al usuario
function auth(req, res) {
    const data = req.body;
    req.getConnection((err, conn) => {
        conn.query('SELECT * FROM users WHERE email = ?', [data.email], (err, userdata) => {
            if (userdata.length > 0) {
                userdata.forEach(element => {
                    bcrypt.compare(data.password, element.password, (err, isMatch) => {
                        if (!isMatch) {
                            res.render('login/index', { error: 'Error: Contraseña incorrecta!' });
                        } else {
                            req.session.loggedin = true;
                            req.session.name = element.name;
                            res.redirect('/');
                        }
                    });
                });
            } else {
                res.render('login/index', { error: 'Error: El usuario no existe!' });
            }
        });
    });
}

// Controlador para la página de registro
function register(req, res) {
    if (req.session.loggedin != true) {
        res.render('login/register');
    } else {
        res.redirect('/');
    }
}

// Controlador para almacenar un nuevo usuario en la base de datos
function storeUser(req, res) {
    const data = req.body;

    req.getConnection((err, conn) => {
        conn.query('SELECT * FROM users WHERE email = ?', [data.email], (err, userdata) => {
            if (userdata.length > 0) {
                res.render('login/register', { error: 'Error: El usuario ya existe!' });
            } else {
                // Verifica que data.password esté definido
                if (data.password) {
                    bcrypt.hash(data.password, 12).then(hash => {
                        data.password = hash;

                        req.getConnection((err, conn) => {
                            conn.query('INSERT INTO users SET ?', [data], (err, rows) => {
                                if (err) {
                                    console.error('Error al insertar usuario:', err);
                                    res.render('login/register', { error: 'Error al registrar el usuario.' });
                                } else {
                                    res.redirect('/');
                                }
                            });
                        });
                    }).catch(err => {
                        console.error('Error al hashear la contraseña:', err);
                        res.render('login/register', { error: 'Error al procesar la contraseña.' });
                    });
                } else {
                    res.render('login/register', { error: 'Contraseña requerida' });
                }
            }
        });
    });
}

// Controlador para cerrar sesión
function logout(req, res) {
    if (req.session.loggedin == true) {
        req.session.destroy();
    }
    res.redirect('/login');
}

// Exporta los controladores
module.exports = {
    login,
    register,
    storeUser,
    auth,
    logout,
};
