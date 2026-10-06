# audit-log-php

[![CI](https://github.com/Ph20sr/audit-log-php/actions/workflows/ci.yml/badge.svg)](https://github.com/Ph20sr/audit-log-php/actions/workflows/ci.yml)
![PHP](https://img.shields.io/badge/php-%3E%3D8.1-777bb4)
![license](https://img.shields.io/badge/license-MIT-blue)

Log de auditoria **à prova de adulteração** para sistemas PHP (CRMs, painéis, ERPs). Ele registra **quem mudou o quê e quando**, guarda só o que mudou (diff), **mascara dados sensíveis** e encadeia os registros por hash. Se alguém alterar ou apagar uma linha direto no banco, `verify()` aponta exatamente qual.

Só usa PDO e funciona com MySQL, MariaDB e SQLite.

## Por que

- **LGPD e contratos**: responder "quem acessou ou alterou os dados deste cliente?"
- **Suporte**: "o plano mudou sozinho" → o histórico mostra quem mudou, de quê para quê e quando
- **Confiança**: um log comum pode ser editado por quem tem acesso ao banco. Aqui, a edição fica evidente.

## Como a cadeia funciona

```
#1  prev = 0000…   hash = H(prev + dados #1)
#2  prev = hash#1  hash = H(prev + dados #2)
#3  prev = hash#2  hash = H(prev + dados #3)
```

| adulteração | o que `verify()` diz |
| --- | --- |
| editou o conteúdo da linha 2 | `brokenAt: 2`: o conteúdo deste registro foi alterado |
| apagou a linha 2 | `brokenAt: 3`: o registro anterior foi apagado ou alterado |
| editou e recalculou o hash | com `secret` (HMAC), não adianta: sem o segredo, o hash recalculado não confere |

## Uso

```php
use Ph20sr\AuditLog\AuditLog;

$audit = new AuditLog($pdo, secret: getenv('AUDIT_SECRET'));
$audit->install(); // cria a tabela audit_log (uma vez)

// Alteração: o diff é calculado sozinho
$audit->record(
    actor: "user:{$user->id}",
    action: 'customer.updated',
    entityType: 'customer',
    entityId: $customer->id,
    before: $antes,
    after: $depois,
    meta: ['ip' => $_SERVER['REMOTE_ADDR']],
);

// Evento sem estado (login, exportação, visualização de dado sensível)
$audit->record("user:{$user->id}", 'report.exported', 'report', 'clientes', meta: ['rows' => 1200]);

$audit->history('customer', 1001);
// [['action' => 'customer.updated', 'actor' => 'user:7', 'changes' => ['plan' => ['basic', 'pro']], 'occurred_at' => '2026-10-06T12:00:01.000Z', ...], ...]

$check = $audit->verify();
if (!$check->ok) {
    alertar("Log de auditoria adulterado no registro {$check->brokenAt}: {$check->reason}");
}
```

### Dados sensíveis

Campos cujo nome contém `password`, `senha`, `token`, `secret`, `api_key`, `card_number` ou `cvv` aparecem no diff como alterados, mas com o valor `[redacted]`, inclusive dentro de `meta` em qualquer nível. A lista é configurável:

```php
new AuditLog($pdo, sensitiveKeys: ['password', 'token', 'rg', 'salario']);
```

### Boas práticas

- Rode `verify()` num cron diário e alerte se falhar
- Guarde o `AUDIT_SECRET` fora do banco (variável de ambiente)
- Dê ao usuário do banco da aplicação só `INSERT` e `SELECT` nessa tabela

## Testes

```bash
composer install
vendor/bin/phpunit
```

Os testes cobrem: registro editado, registro apagado, tentativa de recalcular o hash sem o segredo, mascaramento recursivo e verificação em lotes. O CI roda em PHP 8.1, 8.2 e 8.3.

## Licença

MIT
