<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit\grants;

use baha2odeh\yii2oauth\models\OAuthAccessToken;
use baha2odeh\yii2oauth\models\OAuthAuthCode;
use baha2odeh\yii2oauth\models\OAuthClient;
use baha2odeh\yii2oauth\models\OAuthRefreshToken;
use baha2odeh\yii2oauth\models\OAuthScope;
use baha2odeh\yii2oauth\services\TokenGenerator;
use baha2odeh\yii2oauth\tests\support\MockRequest;
use baha2odeh\yii2oauth\tests\unit\TestCase;

/**
 * Base class for grant integration tests.
 * Provides helpers for seeding clients, scopes and building shared grant config.
 */
abstract class GrantTestCase extends TestCase
{
    protected TokenGenerator $generator;

    protected function setUp(): void
    {
        parent::setUp();
        $this->generator = new TokenGenerator(32);
    }

    /** Seed a confidential client and return it + raw secret. */
    protected function seedConfidentialClient(
        string $clientId,
        string $rawSecret,
        string $grantTypes = 'client_credentials',
        string $scopes = ''
    ): OAuthClient {
        $client = new OAuthClient();
        $client->id = $clientId;
        $client->name = 'Test Client';
        $client->secret = \Yii::$app->security->generatePasswordHash($rawSecret);
        $client->redirect_uris = json_encode(['https://app.test/cb']);
        $client->grant_types = $grantTypes;
        $client->scopes = $scopes ?: null;
        $client->is_confidential = 1;
        $client->is_active = 1;
        $client->require_pkce = 0;
        $client->save(false);

        return $client;
    }

    /** Seed a public client (no secret). */
    protected function seedPublicClient(
        string $clientId,
        string $grantTypes = 'authorization_code,refresh_token',
        int $requirePkce = 0
    ): OAuthClient {
        $client = new OAuthClient();
        $client->id = $clientId;
        $client->name = 'Public Client';
        $client->secret = null;
        $client->redirect_uris = json_encode(['https://app.test/cb']);
        $client->grant_types = $grantTypes;
        $client->scopes = null;
        $client->is_confidential = 0;
        $client->is_active = 1;
        $client->require_pkce = $requirePkce;
        $client->save(false);

        return $client;
    }

    protected function seedScope(string $identifier, int $isDefault = 0): OAuthScope
    {
        $scope = new OAuthScope();
        $scope->identifier = $identifier;
        $scope->description = ucfirst($identifier) . ' access';
        $scope->is_default = $isDefault;
        $scope->save(false);

        return $scope;
    }

    /** Build a shared config array for grants (uses default model classes). */
    protected function grantConfig(array $extra = []): array
    {
        return array_merge([
            'clientModelClass'       => OAuthClient::class,
            'accessTokenModelClass'  => OAuthAccessToken::class,
            'refreshTokenModelClass' => OAuthRefreshToken::class,
            'scopeModelClass'        => OAuthScope::class,
            'tokenGenerator'         => $this->generator,
            'accessTokenTtl'         => 3600,
            'refreshTokenTtl'        => 2592000,
        ], $extra);
    }

    protected function requestWithPost(array $body, string $authHeader = ''): MockRequest
    {
        $req = new MockRequest();
        $req->setBodyParams($body);
        if ($authHeader !== '') {
            $req->setAuthorizationHeader($authHeader);
        }
        return $req;
    }

    protected function requestWithBasicAuth(array $body, string $clientId, string $secret): MockRequest
    {
        $req = new MockRequest();
        $req->setBodyParams($body);
        $req->setBasicAuth($clientId, $secret);
        return $req;
    }

    /** Assert the response has all required OAuth2 token fields. */
    protected function assertTokenResponse(array $response, bool $hasRefreshToken = false): void
    {
        $this->assertArrayHasKey('access_token', $response);
        $this->assertArrayHasKey('token_type', $response);
        $this->assertArrayHasKey('expires_in', $response);
        $this->assertArrayHasKey('scope', $response);
        $this->assertSame('Bearer', $response['token_type']);

        if ($hasRefreshToken) {
            $this->assertArrayHasKey('refresh_token', $response);
            $this->assertNotEmpty($response['refresh_token']);
        } else {
            $this->assertArrayNotHasKey('refresh_token', $response);
        }

        $this->assertNotEmpty($response['access_token']);
        $this->assertGreaterThan(0, $response['expires_in']);
    }
}
