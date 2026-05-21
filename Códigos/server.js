const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const db = require('./db');
const bcrypt = require('bcrypt'); //biblioteca bcrypt

const app = express();
app.use(bodyParser.json());
app.use(express.static('public')); 

// Rota de Cadastro - SEGURA (Com Hashing usndo Byrypt e Salting)
app.post('/register', async (req, res) => {
  const { usuario, senha } = req.body;
  
  try {

    

    console.log("--- NOVO CADASTRO ---");
    console.log("Usuário digitou a senha:", senha);
    console.log("O Node transformou no Hash:", hashSenha);
    console.log("---------------------");

    // Aqui salva o HASH no banco, nunca a senha digitada
    const sql = `INSERT INTO usuarios (usuario, senha) VALUES ('${usuario}', '${hashSenha}')`;
    
    db.query(sql, (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: "Usuário já existe." });
        }
        return res.status(500).json({ message: "Erro ao cadastrar no banco." });
      }
      res.json({ message: "Usuário cadastrado com segurança!" });
    });
  } catch (error) {
    res.status(500).json({ message: "Erro ao processar a senha." });
  }
});

// rota de login 
app.post('/login', (req, res) => {
  const { usuario, senha } = req.body;
  
  console.log("\n====== TENTATIVA DE LOGIN ======");
  console.log(`1. Frontend enviou -> Usuário: [${usuario}] | Senha digitada: [${senha}]`);

  const sql = `SELECT * FROM usuarios WHERE usuario = '${usuario}'`;
  console.log(`2. Executando SQL -> ${sql}`);
  
  db.query(sql, async (err, result) => {
    if (err) {
      console.log("❌ ERRO SQL:", err.message);
      return res.status(500).json({ message: "Erro no banco de dados" });
    }

    if (result && result.length > 0) {
      const usuarioBanco = result[0];
      console.log(`3. Usuário encontrado! -> ID no banco: ${usuarioBanco.id}`);
      console.log(`4. Hash guardado no banco -> ${usuarioBanco.senha}`);

    
      console.log(`5. Bcrypt validou a senha? -> ${senhaValida ? 'SIM ✅' : 'NÃO ❌'}`);

      if (senhaValida) {
        console.log("🔐 STATUS: Acesso Liberado.");
        res.json({ message: "Acesso concedido!", usuarioNoBanco: usuarioBanco.usuario });
      } else {
        console.log("🔒 STATUS: Acesso Negado (Senha não bate com o Hash).");
        res.status(401).json({ message: "Usuário ou senha inválidos" });
      }
    } else {
      console.log("🔒 STATUS: Acesso Negado (Usuário não existe no banco).");
      res.status(401).json({ message: "Usuário ou senha inválidos" });
    }
    console.log("================================\n");
  });
});

// rota de notas
app.get('/api/notes/:id', (req, res) => {
  // uso de concatenação
  const sql = `SELECT * FROM notas WHERE id = ${req.params.id}`;
  
  db.query(sql, (err, result) => {
    if (err) {
      // tratamento de erro
      return res.status(500).json({ message: "Erro ao processar a solicitação." });
    }

    if (result.length > 0) {
      res.json(result[0]);
    } else {
      // tratamento de erro
      res.status(404).json({ message: "Nota não encontrada." });
    }
  });
});

app.listen(3000, () => console.log("Servidor rodando em http://localhost:3000"));