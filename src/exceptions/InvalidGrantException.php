<?php

namespace baha2odeh\yii2oauth\exceptions;

class InvalidGrantException extends OAuthException
{
    public function getErrorCode(): string
    {
        return 'invalid_grant';
    }

    public function getName(): string
    {
        return 'Invalid Grant';
    }
}
