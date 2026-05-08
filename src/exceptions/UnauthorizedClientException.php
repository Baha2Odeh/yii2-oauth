<?php

namespace baha2odeh\yii2oauth\exceptions;

class UnauthorizedClientException extends OAuthException
{
    public function getHttpStatusCode(): int
    {
        return 401;
    }

    public function getErrorCode(): string
    {
        return 'unauthorized_client';
    }

    public function getName(): string
    {
        return 'Unauthorized Client';
    }
}
