const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const db = require('./db');
const bcrypt = require('bcrypt'); //biblioteca bcrypt
const jwt = require('jsonwebtoken');

// em sistemas reais isso fica em .env invisivel
const JWT_SECRET = 'MinhaChaveSuperSecretaEComplicada123!';

const app = express();
app.use(bodyParser.json());
app.use(express.static('public')); 

// Rota de Cadastro - SEGURA (Com Hashing usndo Byrypt e Salting)
app.post('/register', async (req, res) => {
  const { usuario, senha } = req.body;
  
  try {
    const saltRounds = 10;
    // Transforma a senha em um Hash irreversível
    const hashSenha = await bcrypt.hash(senha, saltRounds);

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

      const senhaValida = await bcrypt.compare(senha, usuarioBanco.senha);
      console.log(`5. Bcrypt validou a senha? -> ${senhaValida ? 'SIM ✅' : 'NÃO ❌'}`);

      if (senhaValida) {
        console.log("🔐 STATUS: Acesso Liberado. Gerando JWT...");
        
        // Aplicação da RFC 8725: Payload mínimo + Expiração + Algoritmo Fixo
        const token = jwt.sign(
          { id: usuarioBanco.id, usuario: usuarioBanco.usuario }, // Payload (Carga Útil)
          JWT_SECRET, // A chave que assina
          { 
            expiresIn: '1h', // Expira em 1 hora (Regra de Ouro)
            algorithm: 'HS256' // Trava o algoritmo para evitar falhas de rebaixamento
          }
        );

        // Agora enviamos o token de volta para o navegador
        res.json({ 
            message: "Acesso concedido!", 
            usuarioNoBanco: usuarioBanco.usuario,
            token: token 
        });
      }
    } else {
      console.log("🔒 STATUS: Acesso Negado (Usuário não existe no banco).");
      res.status(401).json({ message: "Usuário ou senha inválidos" });
    }
    console.log("================================\n");
  });
});

// Middleware de Autenticação JWT
function autenticarToken(req, res, next) {
  // O token geralmente vem no cabeçalho HTTP: "Authorization: Bearer <token>"
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: "Acesso Negado: Token não fornecido." });
  }

  // Verifica se o token é válido e se foi assinado com o nosso segredo
  jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'], clockTolerance: 0 }, (err, usuarioDecodificado) => {
    if (err) {
      // Se expirou ou foi fraudado, cai aqui
      return res.status(403).json({ message: "Acesso Negado: Token inválido ou expirado." });
    }
    
    // Se deu tudo certo, guarda os dados do usuário na requisição e permite passar
    req.usuarioLogado = usuarioDecodificado;
    next(); // "Pode abrir a porta e executar a rota solicitada"
  });
}

// rota de notas
app.get('/api/notes/:id', autenticarToken, (req, res) => {
  console.log(`Usuário [${req.usuarioLogado.usuario}] está tentando ler a nota ${req.params.id}`);
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