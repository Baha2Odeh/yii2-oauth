<?php

namespace baha2odeh\yii2oauth\exceptions;

class OAuthException extends \yii\base\Exception
{
    public function getHttpStatusCode(): int
    {
        return 400;
    }

    public function getErrorCode(): string
    {
        return 'oauth_error';
    }

    public function getName(): string
    {
        return 'OAuth Exception';
    }
}
