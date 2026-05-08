<?php

namespace baha2odeh\yii2oauth\services;

class TokenGenerator
{
    public function __construct(private int $tokenBytes = 32)
    {
    }

    /** Generate a cryptographically random opaque token (hex string). */
    public function generate(): string
    {
        return bin2hex(random_bytes($this->tokenBytes));
    }

    /** Hash a raw token for DB storage (SHA-256 hex). */
    public static function hash(string $rawToken): string
    {
        return hash('sha256', $rawToken);
    }
}
