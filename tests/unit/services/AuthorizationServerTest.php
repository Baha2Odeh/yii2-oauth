<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit\services;

use baha2odeh\yii2oauth\contracts\grants\GrantTypeInterface;
use baha2odeh\yii2oauth\exceptions\UnsupportedGrantTypeException;
use baha2odeh\yii2oauth\services\AuthorizationServer;
use baha2odeh\yii2oauth\tests\support\MockRequest;
use PHPUnit\Framework\TestCase;

class AuthorizationServerTest extends TestCase
{
    private AuthorizationServer $server;

    protected function setUp(): void
    {
        $this->server = new AuthorizationServer();
    }

    public function testRegisterAndRetrieveGrant(): void
    {
        $grant = $this->makeGrant('client_credentials');
        $this->server->registerGrant($grant);

        $this->assertSame(['client_credentials' => $grant], $this->server->getGrants());
    }

    public function testRegisterMultipleGrants(): void
    {
        $this->server->registerGrant($this->makeGrant('client_credentials'));
        $this->server->registerGrant($this->makeGrant('authorization_code'));

        $this->assertCount(2, $this->server->getGrants());
    }

    public function testRegisterGrantOverwritesDuplicate(): void
    {
        $g1 = $this->makeGrant('password');
        $g2 = $this->makeGrant('password');

        $this->server->registerGrant($g1);
        $this->server->registerGrant($g2);

        $grants = $this->server->getGrants();
        $this->assertSame($g2, $grants['password']);
    }

    public function testRespondToAccessTokenRequestDispatchesGrant(): void
    {
        $expectedResponse = ['access_token' => 'tok', 'token_type' => 'Bearer', 'expires_in' => 3600, 'scope' => ''];
        $grant = $this->makeGrant('client_credentials', $expectedResponse);
        $this->server->registerGrant($grant);

        $request = new MockRequest();
        $request->setBodyParams(['grant_type' => 'client_credentials']);

        $response = $this->server->respondToAccessTokenRequest($request);

        $this->assertSame($expectedResponse, $response);
    }

    public function testRespondThrowsForUnknownGrantType(): void
    {
        $request = new MockRequest();
        $request->setBodyParams(['grant_type' => 'unknown_grant']);

        $this->expectException(UnsupportedGrantTypeException::class);
        $this->server->respondToAccessTokenRequest($request);
    }

    public function testRespondThrowsForEmptyGrantType(): void
    {
        $request = new MockRequest();
        $request->setBodyParams([]);

        $this->expectException(UnsupportedGrantTypeException::class);
        $this->server->respondToAccessTokenRequest($request);
    }

    public function testValidateAuthorizationRequestDelegatesToMatchingGrant(): void
    {
        $expected = [
            'client' => 'stub', 'redirect_uri' => 'https://app.test/cb', 'scopes' => [], 'state' => null,
            'code_challenge' => null, 'code_challenge_method' => null, 'grant_type' => 'authorization_code',
        ];

        $grant = $this->createMock(GrantTypeInterface::class);
        $grant->method('getIdentifier')->willReturn('authorization_code');
        $grant->method('canRespondToAuthorizationRequest')->willReturn(true);
        $grant->method('validateAuthorizationRequest')->willReturn($expected);

        $this->server->registerGrant($grant);

        $request = new MockRequest();
        $result = $this->server->validateAuthorizationRequest($request);

        $this->assertSame($expected, $result);
    }

    public function testValidateAuthorizationRequestThrowsIfNoneHandle(): void
    {
        $grant = $this->makeGrant('client_credentials');
        $this->server->registerGrant($grant);

        $request = new MockRequest();

        $this->expectException(UnsupportedGrantTypeException::class);
        $this->server->validateAuthorizationRequest($request);
    }

    public function testCompleteAuthorizationRequestDelegatesToGrant(): void
    {
        $redirectUri = 'https://app.test/cb?code=abc&state=xyz';

        $grant = $this->createMock(GrantTypeInterface::class);
        $grant->method('getIdentifier')->willReturn('authorization_code');
        $grant->method('completeAuthorizationRequest')
            ->with(['grant_type' => 'authorization_code'], 'user_1', true)
            ->willReturn($redirectUri);

        $this->server->registerGrant($grant);

        $result = $this->server->completeAuthorizationRequest(
            ['grant_type' => 'authorization_code'],
            'user_1',
            true
        );

        $this->assertSame($redirectUri, $result);
    }

    // ---- Helpers ----

    private function makeGrant(string $identifier, array $tokenResponse = []): GrantTypeInterface
    {
        $grant = $this->createMock(GrantTypeInterface::class);
        $grant->method('getIdentifier')->willReturn($identifier);
        $grant->method('canRespondToAuthorizationRequest')->willReturn(false);
        $grant->method('respondToAccessTokenRequest')->willReturn($tokenResponse);
        return $grant;
    }
}
