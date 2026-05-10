<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit\services;

use baha2odeh\yii2oauth\services\TokenGenerator;
use PHPUnit\Framework\TestCase;

class TokenGeneratorTest extends TestCase
{
    private TokenGenerator $generator;

    protected function setUp(): void
    {
        $this->generator = new TokenGenerator(32);
    }

    public function testGenerateReturnsHexString(): void
    {
        $token = $this->generator->generate();

        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $token);
    }

    public function testGenerateHasCorrectLength(): void
    {
        // 32 bytes → 64 hex chars
        $token = $this->generator->generate();

        $this->assertSame(64, strlen($token));
    }

    public function testGenerateWithCustomByteLength(): void
    {
        $generator = new TokenGenerator(16);
        $token = $generator->generate();

        $this->assertSame(32, strlen($token));
    }

    public function testGenerateProducesUniqueTokens(): void
    {
        $tokens = [];
        for ($i = 0; $i < 20; $i++) {
            $tokens[] = $this->generator->generate();
        }

        $this->assertSame(count($tokens), count(array_unique($tokens)));
    }

    public function testHashReturnsSha256Hex(): void
    {
        $raw = 'test_token';
        $expected = hash('sha256', $raw);

        $this->assertSame($expected, TokenGenerator::hash($raw));
    }

    public function testHashIsDeterministic(): void
    {
        $raw = 'deterministic';

        $this->assertSame(TokenGenerator::hash($raw), TokenGenerator::hash($raw));
    }

    public function testHashLength(): void
    {
        $hash = TokenGenerator::hash($this->generator->generate());

        // SHA-256 produces 64 hex chars
        $this->assertSame(64, strlen($hash));
    }

    public function testHashDiffersFromRaw(): void
    {
        $raw = $this->generator->generate();

        $this->assertNotSame($raw, TokenGenerator::hash($raw));
    }

    public function testRawTokenIsNotStoredHash(): void
    {
        $raw = $this->generator->generate();
        $hash = TokenGenerator::hash($raw);

        // Verify round-trip: hashing raw gives the stored value
        $this->assertSame($hash, hash('sha256', $raw));
    }
}
