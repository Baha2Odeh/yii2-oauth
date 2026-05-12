<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit\models;

use baha2odeh\yii2oauth\models\OAuthAccessToken;
use baha2odeh\yii2oauth\services\TokenGenerator;
use baha2odeh\yii2oauth\tests\unit\TestCase;

class OAuthAccessTokenTest extends TestCase
{
    private function makeToken(array $overrides = []): OAuthAccessToken
    {
        $raw = $overrides['_raw'] ?? bin2hex(random_bytes(32));
        $hash = TokenGenerator::hash($raw);

        $token = new OAuthAccessToken();
        $token->id = $overrides['id'] ?? $hash;
        $token->client_id = $overrides['client_id'] ?? 'test_client';
        $token->user_id = array_key_exists('user_id', $overrides) ? $overrides['user_id'] : '42';
        $token->scopes = array_key_exists('scopes', $overrides) ? $overrides['scopes'] : json_encode(['read', 'write']);
        $token->revoked = $overrides['revoked'] ?? 0;
        $token->expires_at = $overrides['expires_at'] ?? time() + 3600;
        $token->created_at = time();

        $token->save(false);

        if (!array_key_exists('id', $overrides)) {
            $token->setRawToken($raw);
        }

        return $token;
    }

    public function testGetIdentifierReturnsRawTokenWhenSet(): void
    {
        $raw = 'raw_token_value';
        $token = new OAuthAccessToken();
        $token->id = TokenGenerator::hash($raw);
        $token->setRawToken($raw);

        $this->assertSame($raw, $token->getIdentifier());
    }

    public function testGetIdentifierFallsBackToHashWhenRawNotSet(): void
    {
        $hash = TokenGenerator::hash('some_raw');
        $token = new OAuthAccessToken();
        $token->id = $hash;

        $this->assertSame($hash, $token->getIdentifier());
    }

    public function testGetClientId(): void
    {
        $token = $this->makeToken(['client_id' => 'my_client']);
        $this->assertSame('my_client', $token->getClientId());
    }

    public function testGetUserId(): void
    {
        $token = $this->makeToken(['user_id' => '99']);
        $this->assertSame('99', $token->getUserId());
    }

    public function testGetUserIdNullForMachineTokens(): void
    {
        $token = $this->makeToken(['user_id' => null]);
        $this->assertNull($token->getUserId());
    }

    public function testGetScopesDecodesJson(): void
    {
        $token = $this->makeToken(['scopes' => json_encode(['openid', 'profile'])]);
        $this->assertSame(['openid', 'profile'], $token->getScopes());
    }

    public function testGetScopesReturnsEmptyArrayForNull(): void
    {
        $token = $this->makeToken(['scopes' => null]);
        $this->assertSame([], $token->getScopes());
    }

    public function testGetExpiresAt(): void
    {
        $future = time() + 3600;
        $token = $this->makeToken(['expires_at' => $future]);

        $this->assertSame($future, $token->getExpiresAt()->getTimestamp());
    }

    public function testIsRevokedFalseByDefault(): void
    {
        $token = $this->makeToken(['revoked' => 0]);
        $this->assertFalse($token->isRevoked());
    }

    public function testIsRevokedTrue(): void
    {
        $token = $this->makeToken(['revoked' => 1]);
        $this->assertTrue($token->isRevoked());
    }

    public function testFindByRawToken(): void
    {
        $raw = bin2hex(random_bytes(32));
        $hash = TokenGenerator::hash($raw);

        $t = new OAuthAccessToken();
        $t->id = $hash;
        $t->client_id = 'client_x';
        $t->scopes = json_encode([]);
        $t->revoked = 0;
        $t->expires_at = time() + 3600;
        $t->created_at = time();
        $t->save(false);

        $found = OAuthAccessToken::findByRawToken($raw);

        $this->assertNotNull($found);
        $this->assertSame($raw, $found->getIdentifier());
        $this->assertSame('client_x', $found->getClientId());
    }

    public function testFindByRawTokenReturnsNullForRevoked(): void
    {
        $raw = bin2hex(random_bytes(32));
        $t = new OAuthAccessToken();
        $t->id = TokenGenerator::hash($raw);
        $t->client_id = 'client_y';
        $t->scopes = json_encode([]);
        $t->revoked = 1;
        $t->expires_at = time() + 3600;
        $t->created_at = time();
        $t->save(false);

        $this->assertNull(OAuthAccessToken::findByRawToken($raw));
    }

    public function testFindByRawTokenReturnsNullForExpired(): void
    {
        $raw = bin2hex(random_bytes(32));
        $t = new OAuthAccessToken();
        $t->id = TokenGenerator::hash($raw);
        $t->client_id = 'client_z';
        $t->scopes = json_encode([]);
        $t->revoked = 0;
        $t->expires_at = time() - 1;
        $t->created_at = time();
        $t->save(false);

        $this->assertNull(OAuthAccessToken::findByRawToken($raw));
    }

    public function testRevokeByRawToken(): void
    {
        $raw = bin2hex(random_bytes(32));
        $t = new OAuthAccessToken();
        $t->id = TokenGenerator::hash($raw);
        $t->client_id = 'client_rev';
        $t->scopes = json_encode([]);
        $t->revoked = 0;
        $t->expires_at = time() + 3600;
        $t->created_at = time();
        $t->save(false);

        OAuthAccessToken::revokeByRawToken($raw);

        $this->assertNull(OAuthAccessToken::findByRawToken($raw));
    }

    public function testHasActiveTokenReturnsTrueWhenValidTokenExists(): void
    {
        $this->makeToken([
            'user_id' => '10',
            'client_id' => 'app_client',
            'scopes' => json_encode(['profile', 'email']),
        ]);

        $this->assertTrue(OAuthAccessToken::hasActiveToken('10', 'app_client', ['profile', 'email']));
    }

    public function testHasActiveTokenReturnsTrueForSubsetOfScopes(): void
    {
        $this->makeToken([
            'user_id' => '10',
            'client_id' => 'app_client',
            'scopes' => json_encode(['profile', 'email']),
        ]);

        $this->assertTrue(OAuthAccessToken::hasActiveToken('10', 'app_client', ['profile']));
    }

    public function testHasActiveTokenReturnsFalseWhenScopesMissing(): void
    {
        $this->makeToken([
            'user_id' => '10',
            'client_id' => 'app_client',
            'scopes' => json_encode(['profile']),
        ]);

        $this->assertFalse(OAuthAccessToken::hasActiveToken('10', 'app_client', ['profile', 'email']));
    }

    public function testHasActiveTokenReturnsFalseForRevokedToken(): void
    {
        $this->makeToken([
            'user_id' => '10',
            'client_id' => 'app_client',
            'scopes' => json_encode(['profile']),
            'revoked' => 1,
        ]);

        $this->assertFalse(OAuthAccessToken::hasActiveToken('10', 'app_client', ['profile']));
    }

    public function testHasActiveTokenReturnsFalseForExpiredToken(): void
    {
        $this->makeToken([
            'user_id' => '10',
            'client_id' => 'app_client',
            'scopes' => json_encode(['profile']),
            'expires_at' => time() - 1,
        ]);

        $this->assertFalse(OAuthAccessToken::hasActiveToken('10', 'app_client', ['profile']));
    }

    public function testHasActiveTokenReturnsFalseForDifferentUser(): void
    {
        $this->makeToken([
            'user_id' => '10',
            'client_id' => 'app_client',
            'scopes' => json_encode(['profile']),
        ]);

        $this->assertFalse(OAuthAccessToken::hasActiveToken('99', 'app_client', ['profile']));
    }

    public function testHasActiveTokenReturnsFalseForDifferentClient(): void
    {
        $this->makeToken([
            'user_id' => '10',
            'client_id' => 'app_client',
            'scopes' => json_encode(['profile']),
        ]);

        $this->assertFalse(OAuthAccessToken::hasActiveToken('10', 'other_client', ['profile']));
    }

    public function testHasActiveTokenReturnsFalseWhenNoTokenExists(): void
    {
        $this->assertFalse(OAuthAccessToken::hasActiveToken('10', 'app_client', ['profile']));
    }
}
