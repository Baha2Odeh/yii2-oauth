<?php

namespace baha2odeh\yii2oauth\contracts\entities;

interface RefreshTokenEntityInterface
{
    /** Returns the raw refresh token string (not the hash). */
    public function getIdentifier(): string;

    public function getAccessTokenId(): string;

    public function getExpiresAt(): \DateTimeImmutable;

    public function isRevoked(): bool;
}
