<?php

namespace baha2odeh\yii2oauth\contracts\entities;

interface UserEntityInterface
{
    /** String representation of the user's primary key. */
    public function getIdentifier(): string;

    /**
     * Key-value claims returned by the /userinfo endpoint.
     * e.g. ['email' => 'user@example.com', 'name' => 'John Doe']
     */
    public function getClaims(): array;
}
