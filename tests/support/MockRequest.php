<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\support;

/**
 * Minimal Request stub for testing grants and filters without a real HTTP layer.
 */
class MockRequest extends \yii\web\Request
{
    private array $bodyParams = [];
    private array $queryParams = [];
    private string $authorizationHeader = '';

    public function setBodyParams($params): void
    {
        $this->bodyParams = $params;
    }

    public function setQueryParams($params): void
    {
        $this->queryParams = $params;
    }

    public function setAuthorizationHeader(string $header): void
    {
        $this->authorizationHeader = $header;
    }

    public function setBasicAuth(string $clientId, string $clientSecret): void
    {
        $this->authorizationHeader = 'Basic '.base64_encode("{$clientId}:{$clientSecret}");
    }

    // ---- Override yii\web\Request methods ----

    public function getBodyParam($name, $defaultValue = null): mixed
    {
        return $this->bodyParams[$name] ?? $defaultValue;
    }

    public function get($name = null, $defaultValue = null): mixed
    {
        if ($name === null) {
            return $this->queryParams;
        }
        return $this->queryParams[$name] ?? $defaultValue;
    }

    public function post($name = null, $defaultValue = null): mixed
    {
        if ($name === null) {
            return $this->bodyParams;
        }
        return $this->bodyParams[$name] ?? $defaultValue;
    }

    public function getHeaders(): \yii\web\HeaderCollection
    {
        $headers = new \yii\web\HeaderCollection();
        if ($this->authorizationHeader !== '') {
            $headers->set('Authorization', $this->authorizationHeader);
        }
        return $headers;
    }

    public function getIsPost(): bool
    {
        return true;
    }
}
