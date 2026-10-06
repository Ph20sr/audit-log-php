<?php

declare(strict_types=1);

namespace Ph20sr\AuditLog;

use PDO;

/**
 * Log de auditoria encadeado: cada registro guarda o hash do anterior.
 * Alterar, apagar ou inserir um registro no meio quebra a cadeia, e
 * verify() aponta exatamente onde.
 *
 *     $audit = new AuditLog($pdo, secret: getenv('AUDIT_SECRET'));
 *     $audit->record('user:42', 'customer.updated', 'customer', '1001', $before, $after);
 */
final class AuditLog
{
    public const GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';
    private const REDACTED = '[redacted]';
    private const DEFAULT_SENSITIVE = ['password', 'senha', 'token', 'secret', 'api_key', 'card_number', 'cvv', 'cpf_completo'];

    private readonly string $driver;
    /** @var \Closure(): \DateTimeImmutable */
    private \Closure $clock;

    /**
     * @param string|null $secret com segredo, o hash vira HMAC: quem tem acesso
     *                            ao banco mas não ao segredo não consegue
     *                            recalcular a cadeia depois de adulterar
     * @param list<string> $sensitiveKeys campos mascarados no diff
     */
    public function __construct(
        private readonly PDO $pdo,
        private readonly string $table = 'audit_log',
        #[\SensitiveParameter] private readonly ?string $secret = null,
        private readonly array $sensitiveKeys = self::DEFAULT_SENSITIVE,
        ?callable $clock = null,
    ) {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $table)) {
            throw new \InvalidArgumentException("Nome de tabela inválido: {$table}");
        }
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->driver = (string) $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $this->clock = $clock !== null
            ? \Closure::fromCallable($clock)
            : static fn (): \DateTimeImmutable => new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }

    public function install(): void
    {
        $mysql = $this->driver === 'mysql';
        $id = $mysql ? 'BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT';
        $json = $mysql ? 'JSON' : 'TEXT';
        // MySQL não tem CREATE INDEX IF NOT EXISTS: o índice vai no próprio CREATE TABLE
        $inlineIndex = $mysql ? ",\n            INDEX idx_{$this->table}_entity (entity_type, entity_id)" : '';
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS {$this->table} (
            id {$id},
            occurred_at VARCHAR(32) NOT NULL,
            actor VARCHAR(190) NOT NULL,
            action VARCHAR(190) NOT NULL,
            entity_type VARCHAR(100) NOT NULL,
            entity_id VARCHAR(100) NOT NULL,
            changes {$json} NOT NULL,
            meta {$json} NOT NULL,
            prev_hash CHAR(64) NOT NULL,
            hash CHAR(64) NOT NULL{$inlineIndex}
        )");
        if (!$mysql) {
            $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_{$this->table}_entity ON {$this->table} (entity_type, entity_id)");
        }
    }

    /**
     * Calcula o que mudou entre dois estados: [campo => [antes, depois]].
     * Campos sensíveis aparecem como alterados, mas sem os valores.
     *
     * @param array<string, mixed>|null $before
     * @param array<string, mixed>|null $after
     * @return array<string, array{0: mixed, 1: mixed}>
     */
    public function diff(?array $before, ?array $after): array
    {
        $before ??= [];
        $after ??= [];
        $changes = [];
        foreach (array_unique([...array_keys($before), ...array_keys($after)]) as $key) {
            $old = $before[$key] ?? null;
            $new = $after[$key] ?? null;
            if ($old === $new) {
                continue;
            }
            $changes[$key] = $this->isSensitive((string) $key) ? [self::REDACTED, self::REDACTED] : [$old, $new];
        }
        ksort($changes);
        return $changes;
    }

    /**
     * Grava um evento. Use $before/$after para alterações (o diff é calculado)
     * ou só $meta para eventos sem estado (login, exportação, acesso a dado sensível).
     *
     * @param array<string, mixed>|null $before
     * @param array<string, mixed>|null $after
     * @param array<string, mixed> $meta ip, user agent, motivo...
     * @return int id do registro
     */
    public function record(
        string $actor,
        string $action,
        string $entityType,
        string|int $entityId,
        ?array $before = null,
        ?array $after = null,
        array $meta = [],
    ): int {
        $row = [
            'occurred_at' => ($this->clock)()->format('Y-m-d\TH:i:s.v\Z'),
            'actor' => $actor,
            'action' => $action,
            'entity_type' => $entityType,
            'entity_id' => (string) $entityId,
            'changes' => self::json($this->diff($before, $after)),
            'meta' => self::json($this->redact($meta)),
        ];

        $this->pdo->beginTransaction();
        try {
            // Trava a "ponta" da cadeia para dois registros simultâneos não
            // apontarem para o mesmo anterior
            $lock = $this->driver === 'mysql' ? ' FOR UPDATE' : '';
            $prev = $this->pdo->query("SELECT hash FROM {$this->table} ORDER BY id DESC LIMIT 1{$lock}")->fetchColumn();
            $row['prev_hash'] = is_string($prev) ? $prev : self::GENESIS;
            $row['hash'] = $this->hashOf($row);

            $this->pdo->prepare(
                "INSERT INTO {$this->table} (occurred_at, actor, action, entity_type, entity_id, changes, meta, prev_hash, hash)
                 VALUES (:occurred_at, :actor, :action, :entity_type, :entity_id, :changes, :meta, :prev_hash, :hash)",
            )->execute($row);
            $id = (int) $this->pdo->lastInsertId();
            $this->pdo->commit();
            return $id;
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * Percorre a cadeia inteira e recalcula cada hash. Detecta registro
     * alterado, apagado ou inserido fora de ordem.
     */
    public function verify(int $batchSize = 1000): Verification
    {
        $expectedPrev = self::GENESIS;
        $checked = 0;
        $lastId = 0;
        $stmt = $this->pdo->prepare("SELECT * FROM {$this->table} WHERE id > ? ORDER BY id LIMIT {$batchSize}");

        do {
            $stmt->execute([$lastId]);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as $row) {
                $id = (int) $row['id'];
                if (!hash_equals($expectedPrev, (string) $row['prev_hash'])) {
                    return new Verification(false, $checked, $id, 'O registro anterior foi apagado ou alterado (prev_hash não confere)');
                }
                if (!hash_equals($this->hashOf($row), (string) $row['hash'])) {
                    return new Verification(false, $checked, $id, 'O conteúdo deste registro foi alterado (hash não confere)');
                }
                $expectedPrev = (string) $row['hash'];
                $lastId = $id;
                $checked++;
            }
        } while (count($rows) === $batchSize);

        return new Verification(true, $checked);
    }

    /**
     * Histórico de uma entidade, do mais recente para o mais antigo.
     *
     * @return list<array<string, mixed>>
     */
    public function history(string $entityType, string|int $entityId, int $limit = 100): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT * FROM {$this->table} WHERE entity_type = ? AND entity_id = ? ORDER BY id DESC LIMIT " . max(1, min($limit, 1000)),
        );
        $stmt->execute([$entityType, (string) $entityId]);
        return array_map(static function (array $r): array {
            $r['id'] = (int) $r['id'];
            $r['changes'] = json_decode((string) $r['changes'], true);
            $r['meta'] = json_decode((string) $r['meta'], true);
            return $r;
        }, $stmt->fetchAll(PDO::FETCH_ASSOC));
    }

    /** @param array<string, mixed> $row */
    private function hashOf(array $row): string
    {
        // O id não entra no hash (é gerado pelo banco); a ordem vem do prev_hash
        $canonical = implode("\n", [
            $row['prev_hash'], $row['occurred_at'], $row['actor'], $row['action'],
            $row['entity_type'], $row['entity_id'], $row['changes'], $row['meta'],
        ]);
        return $this->secret !== null ? hash_hmac('sha256', $canonical, $this->secret) : hash('sha256', $canonical);
    }

    private function isSensitive(string $key): bool
    {
        $k = strtolower($key);
        foreach ($this->sensitiveKeys as $s) {
            if (str_contains($k, strtolower($s))) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    private function redact(array $data): array
    {
        foreach ($data as $k => $v) {
            if ($this->isSensitive((string) $k)) {
                $data[$k] = self::REDACTED;
            } elseif (is_array($v)) {
                $data[$k] = $this->redact($v);
            }
        }
        return $data;
    }

    private static function json(mixed $value): string
    {
        // JSON canônico: mesma entrada gera sempre a mesma string (e o mesmo hash)
        return json_encode($value === [] ? new \stdClass() : $value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }
}
