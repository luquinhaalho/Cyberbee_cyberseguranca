-- Criação do esquema
CREATE DATABASE gerenciador_notas;
USE gerenciador_notas;

-- Tabela de Usuários notasusuarios
CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario VARCHAR(50) NOT NULL UNIQUE,
    senha VARCHAR(255) NOT NULL 
);

-- Tabela de Notas 
CREATE TABLE notas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    titulo VARCHAR(100) NOT NULL,
    conteudo TEXT NOT NULL, 
    usuario_id INT,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);

INSERT INTO usuarios (usuario, senha) VALUES ('admin', '123456');

USE gerenciador_notas;
INSERT INTO usuarios (usuario, senha) VALUES ('teste2', '123dois');
INSERT INTO notas (id, titulo, conteudo, usuario_id) VALUES ('1', 'Mat', 'Algo', '1');

USE gerenciador_notas;
SELECT * FROM usuarios;
USE gerenciador_notas;
SELECT * FROM notas;