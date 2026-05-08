<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit\models;

use baha2odeh\yii2oauth\models\OAuthRefreshToken;
use baha2odeh\yii2oauth\services\TokenGenerator;
use baha2odeh\yii2oauth\tests\unit\TestCase;

class OAuthRefreshTokenTest extends TestCase
{
    private function persistToken(array $overrides = []): array
    {
        $raw = bin2hex(random_bytes(32));
        $hash = TokenGenerator::hash($raw);

        $t = new OAuthRefreshToken();
        $t->id = $overrides['id'] ?? $hash;
        $t->access_token_id = $overrides['access_token_id'] ?? TokenGenerator::hash(bin2hex(random_bytes(32)));
        $t->revoked = $overrides['revoked'] ?? 0;
        $t->expires_at = $overrides['expires_at'] ?? time() + 3600;
        $t->created_at = time();
        $t->save(false);

        return [$t, $raw];
    }

    public function testSetRawTokenAndGetIdentifier(): void
    {
        $t = new OAuthRefreshToken();
        $t->id = 'hash_value';
        $t->setRawToken('raw_value');

        $this->assertSame('raw_value', $t->getIdentifier());
    }

    public function testGetIdentifierFallsBackToHashWhenRawNotSet(): void
    {
        $t = new OAuthRefreshToken();
        $t->id = 'stored_hash';

        $this->assertSame('stored_hash', $t->getIdentifier());
    }

    public function testGetAccessTokenId(): void
    {
        $atHash = TokenGenerator::hash('fake_at');
        [$token] = $this->persistToken(['access_token_id' => $atHash]);

        $this->assertSame($atHash, $token->getAccessTokenId());
    }

    public function testIsRevokedFalse(): void
    {
        [$token] = $this->persistToken(['revoked' => 0]);
        $this->assertFalse($token->isRevoked());
    }

    public function testIsRevokedTrue(): void
    {
        [$token] = $this->persistToken(['revoked' => 1]);
        $this->assertTrue($token->isRevoked());
    }

    public function testFindByRawToken(): void
    {
        $raw = bin2hex(random_bytes(32));
        $t = new OAuthRefreshToken();
        $t->id = TokenGenerator::hash($raw);
        $t->access_token_id = TokenGenerator::hash('at');
        $t->revoked = 0;
        $t->expires_at = time() + 3600;
        $t->created_at = time();
        $t->save(false);

        $found = OAuthRefreshToken::findByRawToken($raw);

        $this->assertNotNull($found);
        $this->assertSame($raw, $found->getIdentifier());
    }

    public function testFindByRawTokenNullForRevoked(): void
    {
        $raw = bin2hex(random_bytes(32));
        $t = new OAuthRefreshToken();
        $t->id = TokenGenerator::hash($raw);
        $t->access_token_id = TokenGenerator::hash('at2');
        $t->revoked = 1;
        $t->expires_at = time() + 3600;
        $t->created_at = time();
        $t->save(false);

        $this->assertNull(OAuthRefreshToken::findByRawToken($raw));
    }

    public function testFindByRawTokenNullForExpired(): void
    {
        $raw = bin2hex(random_bytes(32));
        $t = new OAuthRefreshToken();
        $t->id = TokenGenerator::hash($raw);
        $t->access_token_id = TokenGenerator::hash('at3');
        $t->revoked = 0;
        $t->expires_at = time() - 1;
        $t->created_at = time();
        $t->save(false);

        $this->assertNull(OAuthRefreshToken::findByRawToken($raw));
    }

    public function testRevokeByRawToken(): void
    {
        $raw = bin2hex(random_bytes(32));
        $t = new OAuthRefreshToken();
        $t->id = TokenGenerator::hash($raw);
        $t->access_token_id = TokenGenerator::hash('at4');
        $t->revoked = 0;
        $t->expires_at = time() + 3600;
        $t->created_at = time();
        $t->save(false);

        OAuthRefreshToken::revokeByRawToken($raw);

        $this->assertNull(OAuthRefreshToken::findByRawToken($raw));
    }

    public function testRevokeByAccessTokenId(): void
    {
        $atId = TokenGenerator::hash('linked_at');
        $raw = bin2hex(random_bytes(32));

        $t = new OAuthRefreshToken();
        $t->id = TokenGenerator::hash($raw);
        $t->access_token_id = $atId;
        $t->revoked = 0;
        $t->expires_at = time() + 3600;
        $t->created_at = time();
        $t->save(false);

        OAuthRefreshToken::revokeByAccessTokenId($atId);

        $this->assertNull(OAuthRefreshToken::findByRawToken($raw));
    }
}
