const mysql = require('mysql2');

const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '0000',
    port: 3306,
    database: 'auth'
})

pool.getConnection((err, connection) => {
    if (err) return "Error connecting to Database";
    console.log("Database Connection Established!");
    connection.release();
})

module.exports = { mysql, pool };