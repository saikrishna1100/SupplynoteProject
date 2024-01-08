const { Pool } = require('pg');

const pool = new Pool({
    host: "localhost",
    user: "postgres",
    password: "krishna789",
    database: "sk",
    port: 5432
});

module.exports = pool;