<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit\grants;

use baha2odeh\yii2oauth\exceptions\InvalidClientException;
use baha2odeh\yii2oauth\exceptions\UnauthorizedClientException;
use baha2odeh\yii2oauth\grants\ClientCredentialsGrant;

class ClientCredentialsGrantTest extends GrantTestCase
{
    private ClientCredentialsGrant $grant;

    protected function setUp(): void
    {
        parent::setUp();
        $this->grant = new ClientCredentialsGrant($this->grantConfig());
    }

    public function testGetIdentifier(): void
    {
        $this->assertSame('client_credentials', $this->grant->getIdentifier());
    }

    public function testSuccessfulTokenIssuance(): void
    {
        $this->seedConfidentialClient('cc_client', 'secret123', 'client_credentials');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'client_credentials', 'scope' => ''],
            'cc_client',
            'secret123'
        );

        $response = $this->grant->respondToAccessTokenRequest($request);

        $this->assertTokenResponse($response, hasRefreshToken: false);
        $this->assertSame(3600, $response['expires_in']);
    }

    public function testSuccessfulTokenWithPostCredentials(): void
    {
        $this->seedConfidentialClient('cc_post_client', 'mysecret', 'client_credentials');

        $request = $this->requestWithPost([
            'grant_type'    => 'client_credentials',
            'client_id'     => 'cc_post_client',
            'client_secret' => 'mysecret',
            'scope'         => '',
        ]);

        $response = $this->grant->respondToAccessTokenRequest($request);

        $this->assertTokenResponse($response, hasRefreshToken: false);
    }

    public function testTokenIsSavedToDatabase(): void
    {
        $this->seedConfidentialClient('cc_db_client', 'dbsecret', 'client_credentials');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'client_credentials'],
            'cc_db_client',
            'dbsecret'
        );

        $response = $this->grant->respondToAccessTokenRequest($request);

        $found = \baha2odeh\yii2oauth\models\OAuthAccessToken::findByRawToken($response['access_token']);
        $this->assertNotNull($found);
        $this->assertSame('cc_db_client', $found->getClientId());
        $this->assertNull($found->getUserId());
    }

    public function testFailsWithWrongSecret(): void
    {
        $this->seedConfidentialClient('cc_bad_secret', 'correct', 'client_credentials');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'client_credentials'],
            'cc_bad_secret',
            'wrong_password'
        );

        $this->expectException(InvalidClientException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testFailsForPublicClient(): void
    {
        $this->seedPublicClient('cc_public', 'client_credentials');

        $request = $this->requestWithPost([
            'grant_type' => 'client_credentials',
            'client_id'  => 'cc_public',
        ]);

        $this->expectException(UnauthorizedClientException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testFailsForDisallowedGrantType(): void
    {
        $this->seedConfidentialClient('cc_wrong_grant', 'secret', 'authorization_code');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'client_credentials'],
            'cc_wrong_grant',
            'secret'
        );

        $this->expectException(InvalidClientException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testFailsForUnknownClient(): void
    {
        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'client_credentials'],
            'nonexistent_client',
            'secret'
        );

        $this->expectException(InvalidClientException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testTokenScopesAreStored(): void
    {
        $this->seedConfidentialClient('cc_scope_client', 'secret', 'client_credentials', 'read,write');
        $this->seedScope('read');
        $this->seedScope('write');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'client_credentials', 'scope' => 'read write'],
            'cc_scope_client',
            'secret'
        );

        $response = $this->grant->respondToAccessTokenRequest($request);

        $token = \baha2odeh\yii2oauth\models\OAuthAccessToken::findByRawToken($response['access_token']);
        $this->assertEqualsCanonicalizing(['read', 'write'], $token->getScopes());
    }

    public function testCannotRespondToAuthorizationRequest(): void
    {
        $request = new \baha2odeh\yii2oauth\tests\support\MockRequest();
        $this->assertFalse($this->grant->canRespondToAuthorizationRequest($request));
    }
}
