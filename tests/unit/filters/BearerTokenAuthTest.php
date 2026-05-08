<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit\filters;

use baha2odeh\yii2oauth\filters\BearerTokenAuth;
use baha2odeh\yii2oauth\models\OAuthAccessToken;
use baha2odeh\yii2oauth\services\TokenGenerator;
use baha2odeh\yii2oauth\tests\unit\TestCase;

class BearerTokenAuthTest extends TestCase
{
    public function testDefaultsAreCorrect(): void
    {
        $filter = new BearerTokenAuth();

        $this->assertFalse($filter->optional);
        $this->assertSame('oauth', $filter->moduleId);
    }

    public function testCanBeConfigured(): void
    {
        $filter = new BearerTokenAuth(['optional' => true, 'moduleId' => 'myoauth']);

        $this->assertTrue($filter->optional);
        $this->assertSame('myoauth', $filter->moduleId);
    }

    /**
     * Verify that a valid raw token stored in the DB can be found via the same lookup
     * path the filter uses (findByRawToken). The filter itself requires a live web
     * application to run; here we test its underlying lookup mechanism.
     */
    public function testFindByRawTokenUsedByFilter(): void
    {
        $raw = bin2hex(random_bytes(32));

        $at = new OAuthAccessToken();
        $at->id = TokenGenerator::hash($raw);
        $at->client_id = 'filter_client';
        $at->user_id = '1';
        $at->scopes = json_encode(['read']);
        $at->revoked = 0;
        $at->expires_at = time() + 3600;
        $at->created_at = time();
        $at->save(false);

        // Simulate what BearerTokenAuth does after extracting the header value
        $token = OAuthAccessToken::findByRawToken($raw);

        $this->assertNotNull($token);
        $this->assertSame($raw, $token->getIdentifier());
        $this->assertSame('filter_client', $token->getClientId());
    }

    public function testRevokedTokenCannotBeFoundByFilter(): void
    {
        $raw = bin2hex(random_bytes(32));

        $at = new OAuthAccessToken();
        $at->id = TokenGenerator::hash($raw);
        $at->client_id = 'filter_client2';
        $at->scopes = json_encode([]);
        $at->revoked = 1; // already revoked
        $at->expires_at = time() + 3600;
        $at->created_at = time();
        $at->save(false);

        $this->assertNull(OAuthAccessToken::findByRawToken($raw));
    }

    public function testExpiredTokenCannotBeFoundByFilter(): void
    {
        $raw = bin2hex(random_bytes(32));

        $at = new OAuthAccessToken();
        $at->id = TokenGenerator::hash($raw);
        $at->client_id = 'filter_client3';
        $at->scopes = json_encode([]);
        $at->revoked = 0;
        $at->expires_at = time() - 60; // expired
        $at->created_at = time();
        $at->save(false);

        $this->assertNull(OAuthAccessToken::findByRawToken($raw));
    }
}
