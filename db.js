const mysql = require("mysql2/promise");


const connectionConfig = {
  host: "localhost",
  user: "root",
  password: "masterkey",
  database: "zappiki",
};


async function getConnection() {
  return mysql.createConnection(connectionConfig);
}

module.exports = { getConnection };
