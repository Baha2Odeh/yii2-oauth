<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit\grants;

use baha2odeh\yii2oauth\exceptions\InvalidGrantException;
use baha2odeh\yii2oauth\exceptions\InvalidRequestException;
use baha2odeh\yii2oauth\exceptions\UnauthorizedClientException;
use baha2odeh\yii2oauth\grants\AuthorizationCodeGrant;
use baha2odeh\yii2oauth\models\OAuthAccessToken;
use baha2odeh\yii2oauth\models\OAuthAuthCode;
use baha2odeh\yii2oauth\models\OAuthRefreshToken;
use baha2odeh\yii2oauth\services\TokenGenerator;
use baha2odeh\yii2oauth\tests\support\MockRequest;

class AuthorizationCodeGrantTest extends GrantTestCase
{
    private AuthorizationCodeGrant $grant;

    protected function setUp(): void
    {
        parent::setUp();

        $this->grant = new AuthorizationCodeGrant(array_merge(
            $this->grantConfig(),
            [
                'authCodeModelClass'   => OAuthAuthCode::class,
                'authCodeTtl'          => 600,
                'requirePkce'          => false,
                'allowedPkceMethods'   => ['S256', 'plain'],
            ]
        ));
    }

    public function testGetIdentifier(): void
    {
        $this->assertSame('authorization_code', $this->grant->getIdentifier());
    }

    public function testCanRespondToAuthorizationRequestWithResponseTypeCode(): void
    {
        $req = new MockRequest();
        $req->setQueryParams(['response_type' => 'code']);

        $this->assertTrue($this->grant->canRespondToAuthorizationRequest($req));
    }

    public function testCannotRespondToAuthorizationRequestWithOtherResponseType(): void
    {
        $req = new MockRequest();
        $req->setQueryParams(['response_type' => 'token']);

        $this->assertFalse($this->grant->canRespondToAuthorizationRequest($req));
    }

    // ---- validateAuthorizationRequest ----

    public function testValidateAuthorizationRequestReturnsStructuredArray(): void
    {
        $this->seedConfidentialClient('ac_val_client', 'secret', 'authorization_code,refresh_token');

        $req = new MockRequest();
        $req->setQueryParams([
            'response_type' => 'code',
            'client_id'     => 'ac_val_client',
            'redirect_uri'  => 'https://app.test/cb',
            'scope'         => '',
            'state'         => 'xyz123',
        ]);

        $result = $this->grant->validateAuthorizationRequest($req);

        $this->assertArrayHasKey('client', $result);
        $this->assertArrayHasKey('redirect_uri', $result);
        $this->assertArrayHasKey('scopes', $result);
        $this->assertArrayHasKey('state', $result);
        $this->assertArrayHasKey('code_challenge', $result);
        $this->assertArrayHasKey('code_challenge_method', $result);
        $this->assertSame('xyz123', $result['state']);
        $this->assertSame('https://app.test/cb', $result['redirect_uri']);
        $this->assertNull($result['code_challenge']);
    }

    public function testValidateFailsOnMissingClientId(): void
    {
        $req = new MockRequest();
        $req->setQueryParams(['response_type' => 'code']);

        $this->expectException(InvalidRequestException::class);
        $this->grant->validateAuthorizationRequest($req);
    }

    public function testValidateFailsOnUnknownClient(): void
    {
        $req = new MockRequest();
        $req->setQueryParams(['response_type' => 'code', 'client_id' => 'ghost_client']);

        $this->expectException(InvalidRequestException::class);
        $this->grant->validateAuthorizationRequest($req);
    }

    public function testValidateFailsOnInvalidRedirectUri(): void
    {
        $this->seedConfidentialClient('ac_redir_client', 'secret', 'authorization_code');

        $req = new MockRequest();
        $req->setQueryParams([
            'response_type' => 'code',
            'client_id'     => 'ac_redir_client',
            'redirect_uri'  => 'https://evil.com/cb',
        ]);

        $this->expectException(InvalidRequestException::class);
        $this->grant->validateAuthorizationRequest($req);
    }

    public function testValidateFailsWhenClientNotAllowedAuthCode(): void
    {
        $this->seedConfidentialClient('ac_wrong_grant', 'secret', 'client_credentials');

        $req = new MockRequest();
        $req->setQueryParams([
            'response_type' => 'code',
            'client_id'     => 'ac_wrong_grant',
            'redirect_uri'  => 'https://app.test/cb',
        ]);

        $this->expectException(UnauthorizedClientException::class);
        $this->grant->validateAuthorizationRequest($req);
    }

    // ---- completeAuthorizationRequest ----

    public function testCompleteApprovedReturnsRedirectWithCode(): void
    {
        $this->seedConfidentialClient('ac_complete_client', 'secret', 'authorization_code');

        $authRequest = [
            'client'               => \baha2odeh\yii2oauth\models\OAuthClient::findActive('ac_complete_client'),
            'redirect_uri'         => 'https://app.test/cb',
            'scopes'               => [],
            'state'                => 'state_abc',
            'code_challenge'       => null,
            'code_challenge_method' => null,
        ];

        $redirectUri = $this->grant->completeAuthorizationRequest($authRequest, 'user_1', true);

        $this->assertStringStartsWith('https://app.test/cb?', $redirectUri);
        $this->assertStringContainsString('code=', $redirectUri);
        $this->assertStringContainsString('state=state_abc', $redirectUri);
    }

    public function testCompleteDeniedReturnsAccessDeniedError(): void
    {
        $this->seedConfidentialClient('ac_deny_client', 'secret', 'authorization_code');

        $authRequest = [
            'client'               => \baha2odeh\yii2oauth\models\OAuthClient::findActive('ac_deny_client'),
            'redirect_uri'         => 'https://app.test/cb',
            'scopes'               => [],
            'state'                => 'state_xyz',
            'code_challenge'       => null,
            'code_challenge_method' => null,
        ];

        $redirectUri = $this->grant->completeAuthorizationRequest($authRequest, 'user_1', false);

        $this->assertStringContainsString('error=access_denied', $redirectUri);
        $this->assertStringContainsString('state=state_xyz', $redirectUri);
        $this->assertStringNotContainsString('code=', $redirectUri);
    }

    public function testAuthCodeIsPersisted(): void
    {
        $this->seedConfidentialClient('ac_persist_client', 'secret', 'authorization_code');

        $authRequest = [
            'client'               => \baha2odeh\yii2oauth\models\OAuthClient::findActive('ac_persist_client'),
            'redirect_uri'         => 'https://app.test/cb',
            'scopes'               => ['read'],
            'state'                => null,
            'code_challenge'       => null,
            'code_challenge_method' => null,
        ];

        $redirectUri = $this->grant->completeAuthorizationRequest($authRequest, 'user_42', true);

        // Extract raw code from the redirect URI
        parse_str(parse_url($redirectUri, PHP_URL_QUERY), $params);
        $rawCode = $params['code'];

        $code = OAuthAuthCode::findByRawCode($rawCode);
        $this->assertNotNull($code);
        $this->assertSame('user_42', $code->getUserId());
        $this->assertSame('ac_persist_client', $code->getClientId());
    }

    // ---- respondToAccessTokenRequest ----

    public function testSuccessfulCodeExchange(): void
    {
        $this->seedConfidentialClient('ac_exchange_client', 'secret', 'authorization_code,refresh_token');

        $rawCode = $this->issueAuthCode('ac_exchange_client', 'user_1', []);

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'authorization_code', 'code' => $rawCode, 'redirect_uri' => 'https://app.test/cb'],
            'ac_exchange_client',
            'secret'
        );

        $response = $this->grant->respondToAccessTokenRequest($request);

        $this->assertTokenResponse($response, hasRefreshToken: true);
    }

    public function testAuthCodeIsRevokedAfterExchange(): void
    {
        $this->seedConfidentialClient('ac_revoke_code_client', 'secret', 'authorization_code,refresh_token');
        $rawCode = $this->issueAuthCode('ac_revoke_code_client', 'user_1', []);

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'authorization_code', 'code' => $rawCode, 'redirect_uri' => 'https://app.test/cb'],
            'ac_revoke_code_client',
            'secret'
        );

        $this->grant->respondToAccessTokenRequest($request);

        // Code must be revoked (single-use)
        $this->assertNull(OAuthAuthCode::findByRawCode($rawCode));
    }

    public function testFailsOnExpiredCode(): void
    {
        $this->seedConfidentialClient('ac_expired_client', 'secret', 'authorization_code');

        $rawCode = bin2hex(random_bytes(32));
        $code = new OAuthAuthCode();
        $code->id = TokenGenerator::hash($rawCode);
        $code->client_id = 'ac_expired_client';
        $code->user_id = '1';
        $code->redirect_uri = 'https://app.test/cb';
        $code->scopes = json_encode([]);
        $code->revoked = 0;
        $code->expires_at = time() - 1; // expired
        $code->created_at = time();
        $code->save(false);

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'authorization_code', 'code' => $rawCode, 'redirect_uri' => 'https://app.test/cb'],
            'ac_expired_client',
            'secret'
        );

        $this->expectException(InvalidGrantException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testFailsOnMissingCode(): void
    {
        $this->seedConfidentialClient('ac_no_code_client', 'secret', 'authorization_code');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'authorization_code', 'redirect_uri' => 'https://app.test/cb'],
            'ac_no_code_client',
            'secret'
        );

        $this->expectException(InvalidRequestException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testFailsOnRedirectUriMismatch(): void
    {
        $this->seedConfidentialClient('ac_redir_mismatch', 'secret', 'authorization_code');
        $rawCode = $this->issueAuthCode('ac_redir_mismatch', 'user_1', []);

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'authorization_code', 'code' => $rawCode, 'redirect_uri' => 'https://evil.com/cb'],
            'ac_redir_mismatch',
            'secret'
        );

        $this->expectException(InvalidGrantException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    // ---- PKCE tests ----

    public function testPkceS256SuccessfulExchange(): void
    {
        $this->seedConfidentialClient('ac_pkce_client', 'secret', 'authorization_code,refresh_token');

        // Generate PKCE pair
        $verifier  = bin2hex(random_bytes(32));
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $rawCode = $this->issueAuthCode('ac_pkce_client', 'user_1', [], $challenge, 'S256');

        $request = $this->requestWithBasicAuth(
            [
                'grant_type'    => 'authorization_code',
                'code'          => $rawCode,
                'redirect_uri'  => 'https://app.test/cb',
                'code_verifier' => $verifier,
            ],
            'ac_pkce_client',
            'secret'
        );

        $response = $this->grant->respondToAccessTokenRequest($request);
        $this->assertTokenResponse($response, hasRefreshToken: true);
    }

    public function testPkceS256FailsOnWrongVerifier(): void
    {
        $this->seedConfidentialClient('ac_pkce_fail_client', 'secret', 'authorization_code');

        $verifier  = bin2hex(random_bytes(32));
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $rawCode = $this->issueAuthCode('ac_pkce_fail_client', 'user_1', [], $challenge, 'S256');

        $request = $this->requestWithBasicAuth(
            [
                'grant_type'    => 'authorization_code',
                'code'          => $rawCode,
                'redirect_uri'  => 'https://app.test/cb',
                'code_verifier' => 'wrong_verifier_value',
            ],
            'ac_pkce_fail_client',
            'secret'
        );

        $this->expectException(InvalidGrantException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testPkceCodeVerifierRequiredWhenChallengeStored(): void
    {
        $this->seedConfidentialClient('ac_pkce_no_verifier', 'secret', 'authorization_code');

        $verifier  = bin2hex(random_bytes(32));
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $rawCode   = $this->issueAuthCode('ac_pkce_no_verifier', 'user_1', [], $challenge, 'S256');

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'authorization_code', 'code' => $rawCode, 'redirect_uri' => 'https://app.test/cb'],
            'ac_pkce_no_verifier',
            'secret'
        );

        // Missing code_verifier when challenge is stored must fail
        $this->expectException(InvalidRequestException::class);
        $this->grant->respondToAccessTokenRequest($request);
    }

    public function testPkcePlainMethod(): void
    {
        $this->seedConfidentialClient('ac_pkce_plain_client', 'secret', 'authorization_code,refresh_token');

        $verifier  = bin2hex(random_bytes(32));
        $rawCode   = $this->issueAuthCode('ac_pkce_plain_client', 'user_1', [], $verifier, 'plain');

        $request = $this->requestWithBasicAuth(
            [
                'grant_type'    => 'authorization_code',
                'code'          => $rawCode,
                'redirect_uri'  => 'https://app.test/cb',
                'code_verifier' => $verifier,
            ],
            'ac_pkce_plain_client',
            'secret'
        );

        $response = $this->grant->respondToAccessTokenRequest($request);
        $this->assertTokenResponse($response, hasRefreshToken: true);
    }

    public function testPkceRequiredByClientFlagFailsWithoutChallenge(): void
    {
        $this->seedPublicClient('ac_pkce_required_client', 'authorization_code', requirePkce: 1);

        $req = new MockRequest();
        $req->setQueryParams([
            'response_type' => 'code',
            'client_id'     => 'ac_pkce_required_client',
            'redirect_uri'  => 'https://app.test/cb',
        ]);

        $this->expectException(InvalidRequestException::class);
        $this->grant->validateAuthorizationRequest($req);
    }

    public function testPkceRequiredByModuleFlagFailsWithoutChallenge(): void
    {
        $grant = new AuthorizationCodeGrant(array_merge(
            $this->grantConfig(),
            ['authCodeModelClass' => OAuthAuthCode::class, 'authCodeTtl' => 600,
             'requirePkce' => true, 'allowedPkceMethods' => ['S256']]
        ));

        $this->seedConfidentialClient('ac_module_pkce_client', 'secret', 'authorization_code');

        $req = new MockRequest();
        $req->setQueryParams([
            'response_type' => 'code',
            'client_id'     => 'ac_module_pkce_client',
            'redirect_uri'  => 'https://app.test/cb',
        ]);

        $this->expectException(InvalidRequestException::class);
        $grant->validateAuthorizationRequest($req);
    }

    public function testAccessTokenIssuedForCorrectUser(): void
    {
        $this->seedConfidentialClient('ac_user_client', 'secret', 'authorization_code,refresh_token');
        $rawCode = $this->issueAuthCode('ac_user_client', 'user_99', []);

        $request = $this->requestWithBasicAuth(
            ['grant_type' => 'authorization_code', 'code' => $rawCode, 'redirect_uri' => 'https://app.test/cb'],
            'ac_user_client',
            'secret'
        );

        $response = $this->grant->respondToAccessTokenRequest($request);

        $at = OAuthAccessToken::findByRawToken($response['access_token']);
        $this->assertSame('user_99', $at->getUserId());
    }

    // ---- Helper ----

    private function issueAuthCode(
        string $clientId,
        string $userId,
        array $scopes,
        ?string $codeChallenge = null,
        ?string $codeChallengeMethod = null
    ): string {
        $rawCode = bin2hex(random_bytes(32));

        $code = new OAuthAuthCode();
        $code->id = TokenGenerator::hash($rawCode);
        $code->client_id = $clientId;
        $code->user_id = $userId;
        $code->redirect_uri = 'https://app.test/cb';
        $code->scopes = json_encode($scopes);
        $code->code_challenge = $codeChallenge;
        $code->code_challenge_method = $codeChallengeMethod;
        $code->revoked = 0;
        $code->expires_at = time() + 600;
        $code->created_at = time();
        $code->save(false);

        return $rawCode;
    }
}
