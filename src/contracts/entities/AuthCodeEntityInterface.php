<?php

namespace baha2odeh\yii2oauth\contracts\entities;

interface AuthCodeEntityInterface
{
    /** Returns the raw authorization code (not the hash). */
    public function getIdentifier(): string;
    public function getClientId(): string;
    public function getUserId(): string;
    public function getRedirectUri(): string;
    public function getScopes(): array;
    public function getCodeChallenge(): ?string;
    public function getCodeChallengeMethod(): ?string;
    public function getExpiresAt(): \DateTimeImmutable;
    public function isRevoked(): bool;
}
