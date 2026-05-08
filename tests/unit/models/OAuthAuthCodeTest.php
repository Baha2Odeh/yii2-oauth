<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit\models;

use baha2odeh\yii2oauth\models\OAuthAuthCode;
use baha2odeh\yii2oauth\services\TokenGenerator;
use baha2odeh\yii2oauth\tests\unit\TestCase;

class OAuthAuthCodeTest extends TestCase
{
    private function persistCode(array $overrides = []): array
    {
        $raw = bin2hex(random_bytes(32));
        $hash = TokenGenerator::hash($raw);

        $code = new OAuthAuthCode();
        $code->id = $overrides['id'] ?? $hash;
        $code->client_id = $overrides['client_id'] ?? 'client_1';
        $code->user_id = $overrides['user_id'] ?? '42';
        $code->redirect_uri = $overrides['redirect_uri'] ?? 'https://app.test/cb';
        $code->scopes = $overrides['scopes'] ?? json_encode(['read']);
        $code->code_challenge = $overrides['code_challenge'] ?? null;
        $code->code_challenge_method = $overrides['code_challenge_method'] ?? null;
        $code->revoked = $overrides['revoked'] ?? 0;
        $code->expires_at = $overrides['expires_at'] ?? time() + 600;
        $code->created_at = time();
        $code->save(false);

        return [$code, $raw];
    }

    public function testSetRawCodeAndGetIdentifier(): void
    {
        $code = new OAuthAuthCode();
        $code->id = 'hash';
        $code->setRawCode('raw_code');

        $this->assertSame('raw_code', $code->getIdentifier());
    }

    public function testGetIdentifierFallsBackToHash(): void
    {
        $code = new OAuthAuthCode();
        $code->id = 'stored_hash';

        $this->assertSame('stored_hash', $code->getIdentifier());
    }

    public function testGetClientId(): void
    {
        [$code] = $this->persistCode(['client_id' => 'my_client']);
        $this->assertSame('my_client', $code->getClientId());
    }

    public function testGetUserId(): void
    {
        [$code] = $this->persistCode(['user_id' => '77']);
        $this->assertSame('77', $code->getUserId());
    }

    public function testGetRedirectUri(): void
    {
        [$code] = $this->persistCode(['redirect_uri' => 'https://example.com/cb']);
        $this->assertSame('https://example.com/cb', $code->getRedirectUri());
    }

    public function testGetScopesDecodesJson(): void
    {
        [$code] = $this->persistCode(['scopes' => json_encode(['openid', 'email'])]);
        $this->assertSame(['openid', 'email'], $code->getScopes());
    }

    public function testGetScopesReturnsEmptyForNull(): void
    {
        [$code] = $this->persistCode(['scopes' => null]);
        $this->assertSame([], $code->getScopes());
    }

    public function testGetCodeChallengeAndMethod(): void
    {
        [$code] = $this->persistCode([
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'S256',
        ]);

        $this->assertSame('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', $code->getCodeChallenge());
        $this->assertSame('S256', $code->getCodeChallengeMethod());
    }

    public function testGetCodeChallengeNullWhenAbsent(): void
    {
        [$code] = $this->persistCode(['code_challenge' => null, 'code_challenge_method' => null]);

        $this->assertNull($code->getCodeChallenge());
        $this->assertNull($code->getCodeChallengeMethod());
    }

    public function testIsRevoked(): void
    {
        [$revoked] = $this->persistCode(['revoked' => 1]);
        [$active] = $this->persistCode(['revoked' => 0]);

        $this->assertTrue($revoked->isRevoked());
        $this->assertFalse($active->isRevoked());
    }

    public function testFindByRawCode(): void
    {
        $raw = bin2hex(random_bytes(32));
        $code = new OAuthAuthCode();
        $code->id = TokenGenerator::hash($raw);
        $code->client_id = 'cl';
        $code->user_id = '1';
        $code->redirect_uri = 'https://x.test/cb';
        $code->scopes = json_encode([]);
        $code->revoked = 0;
        $code->expires_at = time() + 600;
        $code->created_at = time();
        $code->save(false);

        $found = OAuthAuthCode::findByRawCode($raw);

        $this->assertNotNull($found);
        $this->assertSame($raw, $found->getIdentifier());
    }

    public function testFindByRawCodeReturnsNullForExpired(): void
    {
        $raw = bin2hex(random_bytes(32));
        $code = new OAuthAuthCode();
        $code->id = TokenGenerator::hash($raw);
        $code->client_id = 'cl';
        $code->user_id = '1';
        $code->redirect_uri = 'https://x.test/cb';
        $code->scopes = json_encode([]);
        $code->revoked = 0;
        $code->expires_at = time() - 1;
        $code->created_at = time();
        $code->save(false);

        $this->assertNull(OAuthAuthCode::findByRawCode($raw));
    }

    public function testRevokeByRawCode(): void
    {
        $raw = bin2hex(random_bytes(32));
        $code = new OAuthAuthCode();
        $code->id = TokenGenerator::hash($raw);
        $code->client_id = 'cl';
        $code->user_id = '1';
        $code->redirect_uri = 'https://x.test/cb';
        $code->scopes = json_encode([]);
        $code->revoked = 0;
        $code->expires_at = time() + 600;
        $code->created_at = time();
        $code->save(false);

        OAuthAuthCode::revokeByRawCode($raw);

        $this->assertNull(OAuthAuthCode::findByRawCode($raw));
    }
}
