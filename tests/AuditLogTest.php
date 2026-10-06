<?php

declare(strict_types=1);

namespace Ph20sr\AuditLog\Tests;

use PDO;
use Ph20sr\AuditLog\AuditLog;
use PHPUnit\Framework\TestCase;

final class AuditLogTest extends TestCase
{
    private PDO $pdo;
    private AuditLog $audit;
    private int $tick = 0;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->audit = new AuditLog($this->pdo, secret: 'segredo-do-servidor', clock: function (): \DateTimeImmutable {
            return (new \DateTimeImmutable('2026-10-06T12:00:00Z'))->modify('+' . $this->tick++ . ' seconds');
        });
        $this->audit->install();
    }

    private function seed(): void
    {
        $this->audit->record('user:1', 'customer.created', 'customer', 1001, null, ['name' => 'Maria', 'plan' => 'basic']);
        $this->audit->record('user:1', 'customer.updated', 'customer', 1001, ['name' => 'Maria', 'plan' => 'basic'], ['name' => 'Maria', 'plan' => 'pro']);
        $this->audit->record('user:2', 'export.csv', 'report', 'clientes', meta: ['ip' => '203.0.113.7', 'rows' => 120]);
    }

    public function testDiffOnlyKeepsChangedFieldsAndRedactsSecrets(): void
    {
        $diff = $this->audit->diff(
            ['name' => 'Maria', 'email' => 'm@x.com', 'password_hash' => 'abc', 'phone' => null],
            ['name' => 'Maria', 'email' => 'maria@x.com', 'password_hash' => 'def', 'phone' => '11999990000'],
        );
        $this->assertSame([
            'email' => ['m@x.com', 'maria@x.com'],
            'password_hash' => ['[redacted]', '[redacted]'],
            'phone' => [null, '11999990000'],
        ], $diff);
    }

    public function testRecordsHistoryWithDiffAndMeta(): void
    {
        $this->seed();
        $history = $this->audit->history('customer', 1001);

        $this->assertCount(2, $history);
        $this->assertSame('customer.updated', $history[0]['action']);
        $this->assertSame(['plan' => ['basic', 'pro']], $history[0]['changes']);
        $this->assertSame('2026-10-06T12:00:01.000Z', $history[0]['occurred_at']);

        $export = $this->audit->history('report', 'clientes')[0];
        $this->assertSame(['ip' => '203.0.113.7', 'rows' => 120], $export['meta']);
        $this->assertSame([], $export['changes']);
    }

    public function testMetaIsRedactedRecursively(): void
    {
        $this->audit->record('system', 'webhook.received', 'payment', 'pay_1', meta: ['headers' => ['asaas-access-token' => 'xyz', 'ua' => 'Asaas']]);
        $meta = $this->audit->history('payment', 'pay_1')[0]['meta'];
        $this->assertSame(['headers' => ['asaas-access-token' => '[redacted]', 'ua' => 'Asaas']], $meta);
    }

    public function testChainIsValid(): void
    {
        $this->seed();
        $result = $this->audit->verify();
        $this->assertTrue($result->ok);
        $this->assertSame(3, $result->checked);

        $first = $this->pdo->query('SELECT prev_hash FROM audit_log WHERE id = 1')->fetchColumn();
        $this->assertSame(AuditLog::GENESIS, $first);
    }

    public function testDetectsEditedRecord(): void
    {
        $this->seed();
        $this->pdo->exec("UPDATE audit_log SET changes = '{\"plan\":[\"basic\",\"enterprise\"]}' WHERE id = 2");

        $result = $this->audit->verify();
        $this->assertFalse($result->ok);
        $this->assertSame(2, $result->brokenAt);
        $this->assertSame(1, $result->checked);
        $this->assertStringContainsString('conteúdo', (string) $result->reason);
    }

    public function testDetectsDeletedRecord(): void
    {
        $this->seed();
        $this->pdo->exec('DELETE FROM audit_log WHERE id = 2');

        $result = $this->audit->verify();
        $this->assertFalse($result->ok);
        $this->assertSame(3, $result->brokenAt);
        $this->assertStringContainsString('apagado', (string) $result->reason);
    }

    public function testRecomputingWithoutTheSecretDoesNotHelp(): void
    {
        $this->seed();
        // Atacante altera e recalcula o hash com SHA-256 puro (não sabe o segredo)
        $row = $this->pdo->query('SELECT * FROM audit_log WHERE id = 3')->fetch(PDO::FETCH_ASSOC);
        $meta = '{"ip":"10.0.0.1","rows":120}';
        $fake = hash('sha256', implode("\n", [$row['prev_hash'], $row['occurred_at'], $row['actor'], $row['action'], $row['entity_type'], $row['entity_id'], $row['changes'], $meta]));
        $this->pdo->prepare('UPDATE audit_log SET meta = ?, hash = ? WHERE id = 3')->execute([$meta, $fake]);

        $this->assertSame(3, $this->audit->verify()->brokenAt);
    }

    public function testVerifyWorksAcrossBatches(): void
    {
        for ($i = 0; $i < 25; $i++) {
            $this->audit->record('user:1', 'note.added', 'customer', 1001, null, ['n' => $i]);
        }
        $this->assertTrue($this->audit->verify(batchSize: 7)->ok);
        $this->assertSame(25, $this->audit->verify(batchSize: 7)->checked);
    }

    public function testRejectsInvalidTableName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new AuditLog($this->pdo, 'audit; DROP TABLE users');
    }
}
