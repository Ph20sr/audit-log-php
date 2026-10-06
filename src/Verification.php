<?php

declare(strict_types=1);

namespace Ph20sr\AuditLog;

/** Resultado da verificação da cadeia de hashes. */
final class Verification
{
    public function __construct(
        public readonly bool $ok,
        public readonly int $checked,
        public readonly ?int $brokenAt = null,
        public readonly ?string $reason = null,
    ) {
    }
}
