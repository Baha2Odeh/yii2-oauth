<?php

namespace baha2odeh\yii2oauth\grants;

use baha2odeh\yii2oauth\contracts\entities\ClientEntityInterface;
use baha2odeh\yii2oauth\contracts\grants\GrantTypeInterface;
use baha2odeh\yii2oauth\exceptions\InvalidClientException;
use baha2odeh\yii2oauth\exceptions\InvalidRequestException;
use baha2odeh\yii2oauth\exceptions\InvalidScopeException;
use baha2odeh\yii2oauth\models\OAuthAccessToken;
use baha2odeh\yii2oauth\models\OAuthRefreshToken;
use baha2odeh\yii2oauth\services\TokenGenerator;
use yii\web\Request;

abstract class AbstractGrant implements GrantTypeInterface
{
    protected string $clientModelClass;
    protected string $accessTokenModelClass;
    protected string $refreshTokenModelClass;
    protected string $scopeModelClass;
    protected TokenGenerator $tokenGenerator;
    protected int $accessTokenTtl;
    protected int $refreshTokenTtl;

    public function __construct(array $config = [])
    {
        foreach ($config as $key => $value) {
            $this->$key = $value;
        }
    }

    // ---- Client validation ----

    /**
     * Validate client credentials from the request.
     * Checks HTTP Basic Auth header first, then falls back to POST params.
     */
    protected function validateClient(Request $request): ClientEntityInterface
    {
        [$clientId, $clientSecret] = $this->extractClientCredentials($request);

        if (empty($clientId)) {
            throw new InvalidClientException('Client authentication failed: missing client_id.');
        }

        /** @var \baha2odeh\yii2oauth\models\OAuthClient $clientModelClass */
        $clientModelClass = $this->clientModelClass;
        $client = $clientModelClass::validateCredentials($clientId, $clientSecret, $this->getIdentifier());

        if ($client === null) {
            throw new InvalidClientException('Client authentication failed.');
        }

        return $client;
    }

    protected function extractClientCredentials(Request $request): array
    {
        $authHeader = $request->getHeaders()->get('Authorization', '');
        if (str_starts_with($authHeader, 'Basic ')) {
            $decoded = base64_decode(substr($authHeader, 6));
            if (str_contains($decoded, ':')) {
                return explode(':', $decoded, 2);
            }
        }

        return [
            $request->getBodyParam('client_id', ''),
            $request->getBodyParam('client_secret'),
        ];
    }

    // ---- Scope validation ----

    /**
     * Validate and resolve requested scopes against the client's allowed scopes.
     * Returns an array of scope identifiers.
     */
    protected function validateScopes(string $scopeString, ClientEntityInterface $client): array
    {
        /** @var \baha2odeh\yii2oauth\models\OAuthScope $scopeModelClass */
        $scopeModelClass = $this->scopeModelClass;

        $requested = array_filter(array_map('trim', explode(' ', $scopeString)));

        if (empty($requested)) {
            // Fall back to client's default scopes or global defaults
            $defaults = $scopeModelClass::findDefaults();
            $clientAllowed = $client->getAllowedScopes();
            $resolved = [];
            foreach ($defaults as $scope) {
                if (empty($clientAllowed) || in_array($scope->getIdentifier(), $clientAllowed, true)) {
                    $resolved[] = $scope->getIdentifier();
                }
            }
            return $resolved;
        }

        $clientAllowed = $client->getAllowedScopes();
        $resolved = [];

        foreach ($requested as $identifier) {
            $scope = $scopeModelClass::findByIdentifier($identifier);

            if ($scope === null) {
                throw new InvalidScopeException("Unknown scope: {$identifier}");
            }

            if (!empty($clientAllowed) && !in_array($identifier, $clientAllowed, true)) {
                throw new InvalidScopeException("Scope not allowed for this client: {$identifier}");
            }

            $resolved[] = $identifier;
        }

        return $resolved;
    }

    // ---- Token issuance ----

    protected function issueAccessToken(
        ClientEntityInterface $client,
        ?string $userId,
        array $scopes,
        int $ttl
    ): OAuthAccessToken {
        $raw = $this->tokenGenerator->generate();
        $hash = TokenGenerator::hash($raw);

        /** @var OAuthAccessToken $model */
        $model = new $this->accessTokenModelClass();
        $model->id = $hash;
        $model->client_id = $client->getIdentifier();
        $model->user_id = $userId;
        $model->scopes = json_encode($scopes);
        $model->revoked = 0;
        $model->expires_at = time() + $ttl;
        $model->created_at = time();

        if (!$model->save()) {
            throw new \RuntimeException('Failed to persist access token: '.json_encode($model->errors));
        }

        $model->setRawToken($raw);

        return $model;
    }

    protected function issueRefreshToken(OAuthAccessToken $accessToken, int $ttl): OAuthRefreshToken
    {
        $raw = $this->tokenGenerator->generate();
        $hash = TokenGenerator::hash($raw);

        /** @var OAuthRefreshToken $model */
        $model = new $this->refreshTokenModelClass();
        $model->id = $hash;
        // $accessToken->id already holds the SHA-256 hash of the raw token
        $model->access_token_id = $accessToken->id;
        $model->revoked = 0;
        $model->expires_at = time() + $ttl;
        $model->created_at = time();

        if (!$model->save()) {
            throw new \RuntimeException('Failed to persist refresh token: '.json_encode($model->errors));
        }

        $model->setRawToken($raw);

        return $model;
    }

    // ---- Token response builder ----

    protected function buildTokenResponse(
        OAuthAccessToken $accessToken,
        ?OAuthRefreshToken $refreshToken,
        int $ttl
    ): array {
        $response = [
            'access_token' => $accessToken->getIdentifier(),
            'token_type' => 'Bearer',
            'expires_in' => $ttl,
            'scope' => implode(' ', $accessToken->getScopes()),
        ];

        if ($refreshToken !== null) {
            $response['refresh_token'] = $refreshToken->getIdentifier();
        }

        return $response;
    }

    // ---- Default no-ops for authorization code flow ----

    public function canRespondToAuthorizationRequest(Request $request): bool
    {
        return false;
    }

    public function validateAuthorizationRequest(Request $request): array
    {
        throw new InvalidRequestException('This grant does not support authorization requests.');
    }

    public function completeAuthorizationRequest(array $authRequest, string $userId, bool $approved): string
    {
        throw new InvalidRequestException('This grant does not support authorization requests.');
    }
}
