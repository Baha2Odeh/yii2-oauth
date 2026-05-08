<?php

namespace baha2odeh\yii2oauth\services;

use baha2odeh\yii2oauth\contracts\grants\GrantTypeInterface;
use baha2odeh\yii2oauth\exceptions\UnsupportedGrantTypeException;
use yii\web\Request;

class AuthorizationServer
{
    /** @var GrantTypeInterface[] keyed by grant identifier */
    private array $grants = [];

    public function registerGrant(GrantTypeInterface $grant): void
    {
        $this->grants[$grant->getIdentifier()] = $grant;
    }

    /**
     * Dispatch a token request to the matching grant.
     *
     * @throws UnsupportedGrantTypeException
     * @throws \baha2odeh\yii2oauth\exceptions\OAuthException
     */
    public function respondToAccessTokenRequest(Request $request): array
    {
        $grantType = $request->getBodyParam('grant_type', '');

        if (empty($grantType) || !isset($this->grants[$grantType])) {
            throw new UnsupportedGrantTypeException(
                "Grant type '{$grantType}' is not supported."
            );
        }

        return $this->grants[$grantType]->respondToAccessTokenRequest($request);
    }

    /**
     * Find the grant that can handle an authorization request (response_type=code).
     *
     * @throws UnsupportedGrantTypeException
     */
    public function validateAuthorizationRequest(Request $request): array
    {
        foreach ($this->grants as $grant) {
            if ($grant->canRespondToAuthorizationRequest($request)) {
                return $grant->validateAuthorizationRequest($request);
            }
        }

        throw new UnsupportedGrantTypeException('No grant supports this authorization request.');
    }

    /**
     * Complete an authorization request after user consent.
     * The $authRequest array must contain a 'grant_type' key set during validateAuthorizationRequest.
     */
    public function completeAuthorizationRequest(array $authRequest, string $userId, bool $approved): string
    {
        $grantType = $authRequest['grant_type'] ?? 'authorization_code';

        if (!isset($this->grants[$grantType])) {
            throw new UnsupportedGrantTypeException("Grant type '{$grantType}' is not registered.");
        }

        return $this->grants[$grantType]->completeAuthorizationRequest($authRequest, $userId, $approved);
    }

    /** @return GrantTypeInterface[] */
    public function getGrants(): array
    {
        return $this->grants;
    }
}
