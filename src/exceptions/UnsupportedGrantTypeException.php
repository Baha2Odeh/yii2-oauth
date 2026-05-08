<?php

namespace baha2odeh\yii2oauth\exceptions;

class UnsupportedGrantTypeException extends OAuthException
{
    public function getErrorCode(): string
    {
        return 'unsupported_grant_type';
    }

    public function getName(): string
    {
        return 'Unsupported Grant Type';
    }
}
