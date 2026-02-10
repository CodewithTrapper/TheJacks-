const mysql = require('mysql2/promise');

const pool = mysql.createPool({
    host: 'gateway01.eu-central-1.prod.aws.tidbcloud.com',
    port: 4000,
    user: '2i8Kv5Eb6XnYvfM.root',
    password: '2i8Kv5Eb6XnYvfM.root',
    database: 'thejackshoteldb',
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test connection
pool.getConnection()
    .then(conn => {
        console.log('✅ Connected to TiDB - The Jacks Hotel Database');
        conn.release();
    })
    .catch(err => {
        console.error('❌ Database connection failed:', err.message);
    });

module.exports = pool;