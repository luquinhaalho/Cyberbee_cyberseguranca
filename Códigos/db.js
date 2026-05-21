const mysql = require('mysql2');

// credencial exposta
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root', 
  password: '123456', //colocar senha do seu db aqui
  database: 'gerenciador_notas' 
});

connection.connect(err => {
  if (err) {
    console.error("Erro ao conectar ao banco:", err.message);
    return;
  }
  console.log("Banco de dados MySQL conectado!");
});

module.exports = connection;