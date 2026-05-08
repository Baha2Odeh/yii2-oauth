<?php

namespace baha2odeh\yii2oauth\exceptions;

class InvalidRequestException extends OAuthException
{
    public function getErrorCode(): string
    {
        return 'invalid_request';
    }

    public function getName(): string
    {
        return 'Invalid Request';
    }
}
