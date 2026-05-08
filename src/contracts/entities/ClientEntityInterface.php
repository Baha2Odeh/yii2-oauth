<?php

namespace baha2odeh\yii2oauth\contracts\entities;

interface ClientEntityInterface
{
    public function getIdentifier(): string;
    public function getName(): string;
    public function getRedirectUris(): array;
    public function isConfidential(): bool;
    public function isActive(): bool;
    public function getAllowedGrantTypes(): array;
    public function getAllowedScopes(): array;
    public function requiresPkce(): bool;
}
