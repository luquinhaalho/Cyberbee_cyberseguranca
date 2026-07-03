// server.js
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const db = require('./db');
const bcrypt = require('bcrypt'); //biblioteca bcrypt
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser'); // cookies 
const crypto = require('crypto'); // MÓDULO NATIVO DE CRIPTOGRAFIA DO NODE

// em sistemas reais isso fica em .env invisivel
const JWT_SECRET = 'MinhaChaveSuperSecretaEComplicada123!';

// REGRA DO AES-256: A chave precisa ter exatamente 32 caracteres (32 bytes)
const CHAVE_MASTER_AES = Buffer.from('diretoria_segura_com_32_bytes_99', 'utf8');

const app = express();
app.use(bodyParser.json());
app.use(cookieParser()); // inicialização cookies
app.use(express.static('public')); 

// Funções auxiliares para a Criptografia Autenticada AES-256-GCM
function criptografarNota(textoPuro) {
    const iv = crypto.randomBytes(12); // GCM exige IV de 12 bytes aleatórios
    const cipher = crypto.createCipheriv('aes-256-gcm', CHAVE_MASTER_AES, iv);
    
    let criptografado = cipher.update(textoPuro, 'utf8', 'hex');
    criptografado += cipher.final('hex');
    
    const authTag = cipher.getAuthTag().toString('hex'); // Gerando o Lacre de Segurança (Tag)

    // Unificamos a estrutura para salvar na coluna TEXT do MySQL (iv:tag:ciphertext)
    return `${iv.toString('hex')}:${authTag}:${criptografado}`;
}

function descriptografarNota(dadosDoBanco) {
    const [ivHex, tagHex, criptografadoHex] = dadosDoBanco.split(':');
    
    if (!ivHex || !tagHex || !criptografadoHex) {
        throw new Error("Formato de dados corrompido ou inválido.");
    }

    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', CHAVE_MASTER_AES, iv);
    decipher.setAuthTag(tag); // Aplica o lacre para validação automática de integridade
    
    let textoClaro = decipher.update(criptografadoHex, 'hex', 'utf8');
    textoClaro += decipher.final('utf8'); // Se a Tag foi adulterada, estoura o erro aqui
    
    return textoClaro;
}

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

// Rota para CRIAR nota (Protegida com AES-256-GCM no Servidor)
app.post('/api/notes', autenticarToken, (req, res) => {
    const { titulo, conteudo } = req.body;
    
    // BACKEND EXECUTA A CRIPTOGRAFIA ANTES DE SALVAR NO BANCO
    const conteudoSeguro = criptografarNota(conteudo);
    console.log(`[AES-GCM] Salvando dados protegidos (iv:tag:cipher): ${conteudoSeguro.substring(0, 30)}...`);

    const sql = `INSERT INTO notas (usuario_id, titulo, conteudo) VALUES (${req.usuarioLogado.id}, '${titulo}', '${conteudoSeguro}')`;
    
    db.query(sql, (err) => {
        if (err) return res.status(500).json({ message: "Erro ao salvar nota." });
        res.json({ message: "Nota armazenada e blindada com AES-256-GCM!" });
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
      const nota = result[0];
      try {
          // TENTA DESCRIPTOGRAFAR E VERIFICAR INTEGRIDADE DO TEXTO CIFRADO
          const conteudoOriginal = descriptografarNota(nota.conteudo);
          nota.conteudo = conteudoOriginal;
          res.json(nota);
      } catch (error) {
          // tratamento de erro de integridade (Tag de Autenticação GCM violada)
          console.log("🚨 ALERTA DE SEGURANÇA: A tag de integridade do AES-GCM falhou.");
          res.status(400).json({ message: "ERRO DE INTEGRIDADE: Os dados desta nota foram adulterados diretamente no banco de dados!" });
      }
    } else {
      // tratamento de erro
      res.status(404).json({ message: "Nota não encontrada." });
    }
  });
});

app.listen(3000, () => console.log("Servidor rodando em http://localhost:3000"));