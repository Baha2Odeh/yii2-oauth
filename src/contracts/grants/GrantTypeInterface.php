<?php

namespace baha2odeh\yii2oauth\contracts\grants;

use yii\web\Request;

interface GrantTypeInterface
{
    /** The grant_type string this class handles, e.g. 'authorization_code'. */
    public function getIdentifier(): string;

    /**
     * Handle the token request and return the token response array:
     * [
     *   'access_token'  => string,
     *   'token_type'    => 'Bearer',
     *   'expires_in'    => int,
     *   'refresh_token' => string|null,
     *   'scope'         => string,
     * ]
     *
     * @throws \baha2odeh\yii2oauth\exceptions\OAuthException
     */
    public function respondToAccessTokenRequest(Request $request): array;

    /** Returns true if this grant can handle an authorization request (response_type=code). */
    public function canRespondToAuthorizationRequest(Request $request): bool;

    /**
     * Validate an authorization request and return a structured array:
     * [
     *   'client'                 => ClientEntityInterface,
     *   'redirect_uri'           => string,
     *   'scopes'                 => ScopeEntityInterface[],
     *   'state'                  => string|null,
     *   'code_challenge'         => string|null,
     *   'code_challenge_method'  => string|null,
     * ]
     *
     * @throws \baha2odeh\yii2oauth\exceptions\OAuthException
     */
    public function validateAuthorizationRequest(Request $request): array;

    /**
     * Complete the authorization request after user consent.
     *
     * Returns the redirect URI with the code (or error) appended.
     *
     * @throws \baha2odeh\yii2oauth\exceptions\OAuthException
     */
    public function completeAuthorizationRequest(array $authRequest, string $userId, bool $approved): string;
}
