<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit\grants;

use baha2odeh\yii2oauth\exceptions\InvalidGrantException;
use baha2odeh\yii2oauth\exceptions\InvalidRequestException;
use baha2odeh\yii2oauth\grants\PasswordGrant;
use baha2odeh\yii2oauth\tests\support\TestUserModel;

class PasswordGrantTest extends GrantTestCase
{
    private PasswordGrant $grant;

    protected function setUp(): void
    {
        parent::setUp();
        TestUserModel::reset();
        TestUserModel::seed('alice', 'password123', '1');

        $this->grant = new PasswordGrant(array_merge(
            $this->grantConfig(),
            ['userModelClass' => TestUserModel::class]
        ));
    }

    protected function tearDown(): void
    {
        TestUserModel::reset();
        parent::tearDown();
    }

    public function testGetIdentifier(): void
    {
        $this->assertSame('password', $this->grant->getIdentifier());
    }

    public function testSuccessfulTokenIssuance(): void
    {
        $this->seedConfidentialClient('pw_client', 'secret', 'password');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'password', 'username' => 'alice', 'password' => 'password123', 'scope' => ''],
            'pw_client',
            'secret'
        );

        $response = $this->grant->respondToAccessTokenRequest($request);

        $this->assertTokenResponse($response, hasRefreshToken: true);
    }

    public function testAccessTokenIsLinkedToUser(): void
    {
        $this->seedConfidentialClient('pw_user_client', 'secret', 'password');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'password', 'username' => 'alice', 'password' => 'password123'],
            'pw_user_client',
            'secret'
        );

        $response = $this->grant->respondToAccessTokenRequest($request);

        $token = \baha2odeh\yii2oauth\models\OAuthAccessToken::findByRawToken($response['access_token']);
        $this->assertSame('1', $token->getUserId());
    }

    public function testFailsOnWrongPassword(): void
    {
        $this->seedConfidentialClient('pw_bad_pass', 'secret', 'password');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'password', 'username' => 'alice', 'password' => 'wrong_password'],
            'pw_bad_pass',
            'secret'
        );

        $this->expectException(InvalidGrantException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testFailsOnUnknownUser(): void
    {
        $this->seedConfidentialClient('pw_unknown_user', 'secret', 'password');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'password', 'username' => 'ghost', 'password' => 'anything'],
            'pw_unknown_user',
            'secret'
        );

        $this->expectException(InvalidGrantException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testFailsWhenUsernameIsMissing(): void
    {
        $this->seedConfidentialClient('pw_no_user', 'secret', 'password');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'password', 'password' => 'password123'],
            'pw_no_user',
            'secret'
        );

        $this->expectException(InvalidRequestException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testFailsWhenPasswordIsMissing(): void
    {
        $this->seedConfidentialClient('pw_no_pass', 'secret', 'password');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'password', 'username' => 'alice'],
            'pw_no_pass',
            'secret'
        );

        $this->expectException(InvalidRequestException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testRefreshTokenIsStoredAndLinkedToAccessToken(): void
    {
        $this->seedConfidentialClient('pw_rt_client', 'secret', 'password');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'password', 'username' => 'alice', 'password' => 'password123'],
            'pw_rt_client',
            'secret'
        );

        $response = $this->grant->respondToAccessTokenRequest($request);

        $at = \baha2odeh\yii2oauth\models\OAuthAccessToken::findByRawToken($response['access_token']);
        $rt = \baha2odeh\yii2oauth\models\OAuthRefreshToken::findByRawToken($response['refresh_token']);

        $this->assertNotNull($rt);
        $this->assertSame($at->id, $rt->getAccessTokenId());
    }
}
