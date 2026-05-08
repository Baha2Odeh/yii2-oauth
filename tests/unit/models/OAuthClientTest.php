<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit\models;

use baha2odeh\yii2oauth\models\OAuthClient;
use baha2odeh\yii2oauth\tests\unit\TestCase;

class OAuthClientTest extends TestCase
{
    private function makeClient(array $overrides = []): OAuthClient
    {
        $client = new OAuthClient();
        $client->id = $overrides['id'] ?? 'client_' . uniqid();
        $client->name = $overrides['name'] ?? 'Test Client';
        $client->secret = $overrides['secret'] ?? $this->hashPassword('secret123');
        $client->redirect_uris = $overrides['redirect_uris'] ?? json_encode(['https://app.test/cb']);
        $client->grant_types = $overrides['grant_types'] ?? 'authorization_code,refresh_token';
        $client->scopes = $overrides['scopes'] ?? null;
        $client->is_confidential = $overrides['is_confidential'] ?? 1;
        $client->is_active = $overrides['is_active'] ?? 1;
        $client->require_pkce = $overrides['require_pkce'] ?? 0;

        $client->save(false);

        return $client;
    }

    // ---- Entity interface ----

    public function testGetIdentifier(): void
    {
        $client = $this->makeClient(['id' => 'my_client']);
        $this->assertSame('my_client', $client->getIdentifier());
    }

    public function testGetName(): void
    {
        $client = $this->makeClient(['name' => 'My App']);
        $this->assertSame('My App', $client->getName());
    }

    public function testGetRedirectUrisDecodeJson(): void
    {
        $uris = ['https://a.test/cb', 'https://b.test/cb'];
        $client = $this->makeClient(['redirect_uris' => json_encode($uris)]);

        $this->assertSame($uris, $client->getRedirectUris());
    }

    public function testGetAllowedGrantTypesDecodesCsv(): void
    {
        $client = $this->makeClient(['grant_types' => 'authorization_code,refresh_token,password']);

        $this->assertSame(['authorization_code', 'refresh_token', 'password'], $client->getAllowedGrantTypes());
    }

    public function testGetAllowedScopesReturnEmptyWhenNull(): void
    {
        $client = $this->makeClient(['scopes' => null]);

        $this->assertSame([], $client->getAllowedScopes());
    }

    public function testGetAllowedScopesDecodesCsv(): void
    {
        $client = $this->makeClient(['scopes' => 'openid,profile,email']);

        $this->assertSame(['openid', 'profile', 'email'], $client->getAllowedScopes());
    }

    public function testIsConfidentialTrue(): void
    {
        $client = $this->makeClient(['is_confidential' => 1]);
        $this->assertTrue($client->isConfidential());
    }

    public function testIsConfidentialFalse(): void
    {
        $client = $this->makeClient(['is_confidential' => 0, 'secret' => null]);
        $this->assertFalse($client->isConfidential());
    }

    public function testIsActiveTrue(): void
    {
        $client = $this->makeClient(['is_active' => 1]);
        $this->assertTrue($client->isActive());
    }

    public function testIsActiveFalse(): void
    {
        $client = $this->makeClient(['is_active' => 0]);
        $this->assertFalse($client->isActive());
    }

    public function testRequiresPkce(): void
    {
        $client = $this->makeClient(['require_pkce' => 1]);
        $this->assertTrue($client->requiresPkce());
    }

    // ---- Static finders ----

    public function testFindActiveReturnsActiveClient(): void
    {
        $client = $this->makeClient(['id' => 'active_client', 'is_active' => 1]);

        $found = OAuthClient::findActive('active_client');

        $this->assertNotNull($found);
        $this->assertSame('active_client', $found->getIdentifier());
    }

    public function testFindActiveReturnsNullForInactiveClient(): void
    {
        $this->makeClient(['id' => 'inactive_client', 'is_active' => 0]);

        $this->assertNull(OAuthClient::findActive('inactive_client'));
    }

    public function testFindActiveReturnsNullForUnknownClient(): void
    {
        $this->assertNull(OAuthClient::findActive('does_not_exist'));
    }

    public function testValidateCredentialsSucceeds(): void
    {
        $rawSecret = 'correct_secret';
        $this->makeClient([
            'id'         => 'valid_client',
            'secret'     => $this->hashPassword($rawSecret),
            'grant_types' => 'client_credentials',
            'is_active'  => 1,
        ]);

        $result = OAuthClient::validateCredentials('valid_client', $rawSecret, 'client_credentials');

        $this->assertNotNull($result);
        $this->assertSame('valid_client', $result->getIdentifier());
    }

    public function testValidateCredentialsFailsOnWrongSecret(): void
    {
        $this->makeClient([
            'id'         => 'bad_secret_client',
            'secret'     => $this->hashPassword('correct'),
            'grant_types' => 'client_credentials',
        ]);

        $result = OAuthClient::validateCredentials('bad_secret_client', 'wrong', 'client_credentials');

        $this->assertNull($result);
    }

    public function testValidateCredentialsFailsOnDisallowedGrant(): void
    {
        $this->makeClient([
            'id'         => 'grant_mismatch_client',
            'secret'     => $this->hashPassword('secret'),
            'grant_types' => 'authorization_code',
        ]);

        $result = OAuthClient::validateCredentials('grant_mismatch_client', 'secret', 'client_credentials');

        $this->assertNull($result);
    }

    public function testValidateCredentialsFailsForInactiveClient(): void
    {
        $this->makeClient([
            'id'         => 'inactive_check',
            'secret'     => $this->hashPassword('secret'),
            'grant_types' => 'client_credentials',
            'is_active'  => 0,
        ]);

        $this->assertNull(OAuthClient::validateCredentials('inactive_check', 'secret', 'client_credentials'));
    }
}
