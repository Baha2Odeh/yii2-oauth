<?php

namespace baha2odeh\yii2oauth\exceptions;

class InvalidScopeException extends OAuthException
{
    public function getErrorCode(): string
    {
        return 'invalid_scope';
    }

    public function getName(): string
    {
        return 'Invalid Scope';
    }
}
