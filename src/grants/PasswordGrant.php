<?php

namespace baha2odeh\yii2oauth\grants;

use baha2odeh\yii2oauth\contracts\entities\UserEntityInterface;
use baha2odeh\yii2oauth\exceptions\InvalidGrantException;
use baha2odeh\yii2oauth\exceptions\InvalidRequestException;
use yii\web\Request;

class PasswordGrant extends AbstractGrant
{
    protected string $userModelClass;

    public function getIdentifier(): string
    {
        return 'password';
    }

    public function respondToAccessTokenRequest(Request $request): array
    {
        $client = $this->validateClient($request);

        $username = $request->getBodyParam('username', '');
        $password = $request->getBodyParam('password', '');

        if (empty($username)) {
            throw new InvalidRequestException('Missing username.');
        }

        if (empty($password)) {
            throw new InvalidRequestException('Missing password.');
        }

        $user = $this->validateUser($username, $password);

        $scopes = $this->validateScopes($request->getBodyParam('scope', ''), $client);
        $accessToken = $this->issueAccessToken($client, $user->getIdentifier(), $scopes, $this->accessTokenTtl);
        $refreshToken = $this->issueRefreshToken($accessToken, $this->refreshTokenTtl);

        return $this->buildTokenResponse($accessToken, $refreshToken, $this->accessTokenTtl);
    }

    /**
     * Authenticate user by credentials.
     * Override this method or extend the grant if you need custom auth logic.
     * The default implementation calls findByCredentials() on the configured userModelClass.
     */
    protected function validateUser(string $username, string $password): UserEntityInterface
    {
        $userModelClass = $this->userModelClass;

        if (!method_exists($userModelClass, 'findByCredentials')) {
            throw new \RuntimeException(
                "{$userModelClass} must implement a static findByCredentials(username, password) method."
            );
        }

        $user = $userModelClass::findByCredentials($username, $password);

        if ($user === null) {
            throw new InvalidGrantException('Invalid username or password.');
        }

        return $user;
    }
}
