<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit\exceptions;

use baha2odeh\yii2oauth\exceptions\InvalidClientException;
use baha2odeh\yii2oauth\exceptions\InvalidGrantException;
use baha2odeh\yii2oauth\exceptions\InvalidRequestException;
use baha2odeh\yii2oauth\exceptions\InvalidScopeException;
use baha2odeh\yii2oauth\exceptions\OAuthException;
use baha2odeh\yii2oauth\exceptions\UnauthorizedClientException;
use baha2odeh\yii2oauth\exceptions\UnsupportedGrantTypeException;
use PHPUnit\Framework\TestCase;

class OAuthExceptionTest extends TestCase
{
    public function testBaseExceptionDefaults(): void
    {
        $e = new OAuthException('Something went wrong');

        $this->assertSame('Something went wrong', $e->getMessage());
        $this->assertSame(400, $e->getHttpStatusCode());
        $this->assertInstanceOf(\Throwable::class, $e);
    }

    public function testInvalidClientException(): void
    {
        $e = new InvalidClientException('bad client');

        $this->assertSame(401, $e->getHttpStatusCode());
        $this->assertSame('invalid_client', $e->getErrorCode());
        $this->assertInstanceOf(OAuthException::class, $e);
    }

    public function testInvalidGrantException(): void
    {
        $e = new InvalidGrantException('bad grant');

        $this->assertSame(400, $e->getHttpStatusCode());
        $this->assertSame('invalid_grant', $e->getErrorCode());
    }

    public function testInvalidRequestException(): void
    {
        $e = new InvalidRequestException('missing param');

        $this->assertSame(400, $e->getHttpStatusCode());
        $this->assertSame('invalid_request', $e->getErrorCode());
    }

    public function testInvalidScopeException(): void
    {
        $e = new InvalidScopeException('bad scope');

        $this->assertSame(400, $e->getHttpStatusCode());
        $this->assertSame('invalid_scope', $e->getErrorCode());
    }

    public function testUnauthorizedClientException(): void
    {
        $e = new UnauthorizedClientException('not allowed');

        $this->assertSame(401, $e->getHttpStatusCode());
        $this->assertSame('unauthorized_client', $e->getErrorCode());
    }

    public function testUnsupportedGrantTypeException(): void
    {
        $e = new UnsupportedGrantTypeException('unknown grant');

        $this->assertSame(400, $e->getHttpStatusCode());
        $this->assertSame('unsupported_grant_type', $e->getErrorCode());
    }

    public function testExceptionChaining(): void
    {
        $original = new \RuntimeException('DB error');
        // Yii2 Exception constructor: __construct($message, $code = 0, $previous = null)
        $e = new InvalidGrantException('wrapped', 0, $original);

        $this->assertSame($original, $e->getPrevious());
    }
}
