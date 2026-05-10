<?php

namespace baha2odeh\yii2oauth\contracts\entities;

interface ScopeEntityInterface
{
    public function getIdentifier(): string;

    public function getDescription(): ?string;

    public function isDefault(): bool;
}
