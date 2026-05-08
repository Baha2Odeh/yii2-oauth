<?php

namespace baha2odeh\yii2oauth\exceptions;

class InvalidClientException extends OAuthException
{
    public function getHttpStatusCode(): int
    {
        return 401;
    }

    public function getErrorCode(): string
    {
        return 'invalid_client';
    }

    public function getName(): string
    {
        return 'Invalid Client';
    }
}
