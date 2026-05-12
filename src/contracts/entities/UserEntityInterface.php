<?php

namespace baha2odeh\yii2oauth\contracts\entities;

interface UserEntityInterface
{
    /** String representation of the user's primary key. */
    public function getIdentifier(): string;

    /**
     * Key-value claims returned by the /userinfo endpoint.
     * Filter returned claims based on the granted $scopes (e.g. 'profile', 'email').
     * e.g. ['email' => 'user@example.com', 'name' => 'John Doe']
     *
     * @param string[] $scopes Scopes granted to the token requesting userinfo.
     */
    public function getClaims(array $scopes = []): array;
}
