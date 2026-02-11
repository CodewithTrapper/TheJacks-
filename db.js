const mysql = require('mysql2/promise');

// Use environment variables for ALL connection details
const pool = mysql.createPool({
    host: process.env.TIDB_HOST || 'gateway01.eu-central-1.prod.aws.tidbcloud.com',
    port: parseInt(process.env.TIDB_PORT) || 4000,
    user: process.env.TIDB_USER || '2i8Kv5Eb6XnYvfM.root',
    password: process.env.TIDB_PASSWORD || '2i8Kv5Eb6XnYvfM.root',
    database: process.env.TIDB_DATABASE || 'thejackshoteldb',
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
    },
    waitForConnections: true,
    connectionLimit: 5, // Reduced for serverless
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
});

// Remove automatic connection test - will test on first query instead

module.exports = pool;