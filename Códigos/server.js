const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const db = require('./db');
const bcrypt = require('bcrypt'); //biblioteca bcrypt
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser'); // cookies 

// em sistemas reais isso fica em .env invisivel
const JWT_SECRET = 'MinhaChaveSuperSecretaEComplicada123!';

const app = express();
app.use(bodyParser.json());
app.use(cookieParser()); // inicialização cookies
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
        
        const token = jwt.sign(
          { id: usuarioBanco.id, usuario: usuarioBanco.usuario }, 
          JWT_SECRET, 
          { expiresIn: '1h', algorithm: 'HS256' }
        );

        // CONFIGURAÇÃO DO COOKIE HTTP-ONLY
        res.cookie('token', token, {
            httpOnly: true, // Impede acesso via JavaScript (Proteção contra XSS)
            secure: false,  // Em produção com HTTPS, mude para true
            sameSite: 'Strict', // Proteção contra envio forçado de formulários falsos (CSRF)
            maxAge: 3600000 // Tempo de vida do cookie (1 hora em milissegundos)
        });

        // token NÃO vai mais no JSON!
        res.json({ 
            message: "Acesso concedido!", 
            usuarioNoBanco: usuarioBanco.usuario 
        });
      }
    } else {
      console.log("🔒 STATUS: Acesso Negado (Usuário não existe no banco).");
      res.status(401).json({ message: "Usuário ou senha inválidos" });
    }
    console.log("================================\n");
  });
});

// Rota para apagar o Cookie no Logout
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: "Logout efetuado com sucesso" });
});


// Middleware de Autenticação JWT com o cookie
function autenticarToken(req, res, next) {
  // Pega o token automaticamente de dentro do cookie
  const token = req.cookies.token; 

  if (!token) {
    return res.status(401).json({ message: "Acesso Negado: Token não fornecido." });
  }

  jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'], clockTolerance: 0 }, (err, usuarioDecodificado) => {
    if (err) {
      return res.status(403).json({ message: "Acesso Negado: Token inválido ou expirado." });
    }
    
    req.usuarioLogado = usuarioDecodificado;
    next(); 
  });
}

// Rota para CRIAR nota (O servidor é cego ao conteúdo)
app.post('/api/notes', autenticarToken, (req, res) => {
    const { titulo, conteudo } = req.body;
    
    // O servidor simplesmente pega o que veio e joga no banco.
    // Ele não faz ideia de que o 'conteudo' está criptografado.
    console.log(`[Zero-Knowledge] Salvando dados cegos: ${conteudo.substring(0, 20)}...`);

    const sql = `INSERT INTO notas (usuario_id, titulo, conteudo) VALUES (${req.usuarioLogado.id}, '${titulo}', '${conteudo}')`;
    
    db.query(sql, (err) => {
        if (err) return res.status(500).json({ message: "Erro ao salvar nota." });
        res.json({ message: "Nota salva no servidor hostil com sucesso!" });
    });
});


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