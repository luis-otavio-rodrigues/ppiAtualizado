<?php
declare(strict_types=1);
require_once __DIR__ . '/config.php';

if (!in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true)) {
    http_response_code(403); exit('Este instalador só pode ser executado localmente.');
}

$pdo = db();
$exists = (int)$pdo->query("SELECT COUNT(*) FROM usuarios WHERE tipo = 'admin'")->fetchColumn();
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $exists === 0) {
    $nome = trim((string)($_POST['nome'] ?? 'Administrador'));
    $email = strtolower(trim((string)($_POST['email'] ?? '')));
    $senha = (string)($_POST['senha'] ?? '');
    if ($nome === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($senha) < 6) {
        $message = 'Preencha nome, e-mail válido e senha com pelo menos 6 caracteres.';
    } else {
        $check = $pdo->prepare('SELECT id FROM usuarios WHERE email = ?');
        $check->execute([$email]);
        if ($check->fetch()) {
            $message = 'Esse e-mail já está cadastrado.';
        } else {
            $stmt = $pdo->prepare("INSERT INTO usuarios (nome, email, tipo, idade, cidade, senha_hash) VALUES (?, ?, 'admin', 18, '—', ?)");
            $stmt->execute([$nome, $email, password_hash($senha, PASSWORD_DEFAULT)]);
            $message = 'Administrador criado com sucesso. APAGUE o arquivo setup_admin.php agora.';
            $exists = 1;
        }
    }
}
?><!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>SunSafe - Criar administrador</title>
<style>body{font-family:Arial,sans-serif;background:#f5f7fb;padding:40px}.box{max-width:460px;margin:auto;background:#fff;padding:28px;border-radius:16px;box-shadow:0 8px 30px #0001}label{display:block;margin-top:14px;font-weight:700}input{width:100%;box-sizing:border-box;padding:11px;margin-top:6px;border:1px solid #ccd3df;border-radius:8px}button{margin-top:20px;padding:12px 18px;border:0;border-radius:8px;background:#ff9f1c;font-weight:700;cursor:pointer}.msg{padding:12px;background:#eef8f2;margin-bottom:14px;border-radius:8px}</style>
<div class="box"><h1>SunSafe — Administrador</h1><p>Use esta página apenas uma vez para criar a conta administrativa.</p><?php if ($message): ?><div class="msg"><?=htmlspecialchars($message, ENT_QUOTES, 'UTF-8')?></div><?php endif; ?><?php if ($exists === 0): ?><form method="post"><label>Nome<input name="nome" value="Administrador" required></label><label>E-mail<input name="email" type="email" required></label><label>Senha<input name="senha" type="password" minlength="6" required></label><button>Criar administrador</button></form><?php else: ?><p>Já existe uma conta administrativa. Remova <code>setup_admin.php</code> da pasta do projeto.</p><?php endif; ?></div>
