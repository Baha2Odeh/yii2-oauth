<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit\grants;

use baha2odeh\yii2oauth\exceptions\InvalidGrantException;
use baha2odeh\yii2oauth\exceptions\InvalidRequestException;
use baha2odeh\yii2oauth\exceptions\InvalidScopeException;
use baha2odeh\yii2oauth\grants\RefreshTokenGrant;
use baha2odeh\yii2oauth\models\OAuthAccessToken;
use baha2odeh\yii2oauth\models\OAuthRefreshToken;
use baha2odeh\yii2oauth\services\TokenGenerator;

class RefreshTokenGrantTest extends GrantTestCase
{
    private RefreshTokenGrant $grant;

    protected function setUp(): void
    {
        parent::setUp();
        $this->grant = new RefreshTokenGrant($this->grantConfig());
    }

    public function testGetIdentifier(): void
    {
        $this->assertSame('refresh_token', $this->grant->getIdentifier());
    }

    public function testSuccessfulRefresh(): void
    {
        $this->seedConfidentialClient('rt_client', 'secret', 'refresh_token');
        [$atRaw, $rtRaw] = $this->seedTokenPair('rt_client', '5', ['read']);

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'refresh_token', 'refresh_token' => $rtRaw],
            'rt_client',
            'secret'
        );

        $response = $this->grant->respondToAccessTokenRequest($request);

        $this->assertTokenResponse($response, hasRefreshToken: true);
        // New tokens must be different from the old ones
        $this->assertNotSame($atRaw, $response['access_token']);
        $this->assertNotSame($rtRaw, $response['refresh_token']);
    }

    public function testOldTokensAreRevokedAfterRefresh(): void
    {
        $this->seedConfidentialClient('rt_revoke_client', 'secret', 'refresh_token');
        [$atRaw, $rtRaw] = $this->seedTokenPair('rt_revoke_client', '6', ['read']);

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'refresh_token', 'refresh_token' => $rtRaw],
            'rt_revoke_client',
            'secret'
        );

        $this->grant->respondToAccessTokenRequest($request);

        // Old tokens should no longer be findable
        $this->assertNull(OAuthAccessToken::findByRawToken($atRaw));
        $this->assertNull(OAuthRefreshToken::findByRawToken($rtRaw));
    }

    public function testNewTokensAreStoredInDatabase(): void
    {
        $this->seedConfidentialClient('rt_new_client', 'secret', 'refresh_token');
        [, $rtRaw] = $this->seedTokenPair('rt_new_client', '7', ['read']);

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'refresh_token', 'refresh_token' => $rtRaw],
            'rt_new_client',
            'secret'
        );

        $response = $this->grant->respondToAccessTokenRequest($request);

        $newAt = OAuthAccessToken::findByRawToken($response['access_token']);
        $newRt = OAuthRefreshToken::findByRawToken($response['refresh_token']);

        $this->assertNotNull($newAt);
        $this->assertNotNull($newRt);
        $this->assertSame($newAt->id, $newRt->getAccessTokenId());
    }

    public function testFailsOnMissingRefreshToken(): void
    {
        $this->seedConfidentialClient('rt_missing', 'secret', 'refresh_token');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'refresh_token'],
            'rt_missing',
            'secret'
        );

        $this->expectException(InvalidRequestException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testFailsOnExpiredRefreshToken(): void
    {
        $this->seedConfidentialClient('rt_exp_client', 'secret', 'refresh_token');

        $atRaw = bin2hex(random_bytes(32));
        $rtRaw = bin2hex(random_bytes(32));
        $at = $this->persistAccessToken($atRaw, 'rt_exp_client', '8', ['read'], time() + 3600);
        $this->persistRefreshToken($rtRaw, $at->id, time() - 1); // expired

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'refresh_token', 'refresh_token' => $rtRaw],
            'rt_exp_client',
            'secret'
        );

        $this->expectException(InvalidGrantException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testFailsWhenRefreshTokenBelongsToDifferentClient(): void
    {
        $this->seedConfidentialClient('rt_client_a', 'secret', 'refresh_token');
        $this->seedConfidentialClient('rt_client_b', 'secret', 'refresh_token');

        [, $rtRaw] = $this->seedTokenPair('rt_client_a', '9', ['read']);

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'refresh_token', 'refresh_token' => $rtRaw],
            'rt_client_b', // different client
            'secret'
        );

        $this->expectException(InvalidGrantException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testScopeCanBeRestrictedOnRefresh(): void
    {
        $this->seedConfidentialClient('rt_scope_client', 'secret', 'refresh_token');
        $this->seedScope('read');
        $this->seedScope('write');
        [, $rtRaw] = $this->seedTokenPair('rt_scope_client', '10', ['read', 'write']);

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'refresh_token', 'refresh_token' => $rtRaw, 'scope' => 'read'],
            'rt_scope_client',
            'secret'
        );

        $response = $this->grant->respondToAccessTokenRequest($request);

        $newAt = OAuthAccessToken::findByRawToken($response['access_token']);
        $this->assertSame(['read'], $newAt->getScopes());
    }

    public function testCannotExpandScopeOnRefresh(): void
    {
        $this->seedConfidentialClient('rt_expand_client', 'secret', 'refresh_token', 'read,write');
        $this->seedScope('read');
        $this->seedScope('write');
        $this->seedScope('admin');
        [, $rtRaw] = $this->seedTokenPair('rt_expand_client', '11', ['read']);

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'refresh_token', 'refresh_token' => $rtRaw, 'scope' => 'read admin'],
            'rt_expand_client',
            'secret'
        );

        $this->expectException(InvalidScopeException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    // ---- Helpers ----

    /** Returns [rawAccessToken, rawRefreshToken]. */
    private function seedTokenPair(string $clientId, string $userId, array $scopes): array
    {
        $atRaw = bin2hex(random_bytes(32));
        $rtRaw = bin2hex(random_bytes(32));

        $at = $this->persistAccessToken($atRaw, $clientId, $userId, $scopes, time() + 3600);
        $this->persistRefreshToken($rtRaw, $at->id, time() + 2592000);

        return [$atRaw, $rtRaw];
    }

    private function persistAccessToken(string $raw, string $clientId, string $userId, array $scopes, int $expiresAt): OAuthAccessToken
    {
        $at = new OAuthAccessToken();
        $at->id = TokenGenerator::hash($raw);
        $at->client_id = $clientId;
        $at->user_id = $userId;
        $at->scopes = json_encode($scopes);
        $at->revoked = 0;
        $at->expires_at = $expiresAt;
        $at->created_at = time();
        $at->save(false);

        return $at;
    }

    private function persistRefreshToken(string $raw, string $accessTokenId, int $expiresAt): OAuthRefreshToken
    {
        $rt = new OAuthRefreshToken();
        $rt->id = TokenGenerator::hash($raw);
        $rt->access_token_id = $accessTokenId;
        $rt->revoked = 0;
        $rt->expires_at = $expiresAt;
        $rt->created_at = time();
        $rt->save(false);

        return $rt;
    }
}
