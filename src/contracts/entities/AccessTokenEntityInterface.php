<?php

namespace baha2odeh\yii2oauth\contracts\entities;

interface AccessTokenEntityInterface
{
    /** Returns the raw token string (not the hash). */
    public function getIdentifier(): string;
    public function getClientId(): string;
    public function getUserId(): ?string;
    public function getScopes(): array;
    public function getExpiresAt(): \DateTimeImmutable;
    public function isRevoked(): bool;
}
