<?php

namespace baha2odeh\yii2oauth\grants;

use baha2odeh\yii2oauth\exceptions\InvalidGrantException;
use baha2odeh\yii2oauth\exceptions\InvalidRequestException;
use baha2odeh\yii2oauth\exceptions\InvalidScopeException;
use baha2odeh\yii2oauth\services\TokenGenerator;
use yii\web\Request;

class RefreshTokenGrant extends AbstractGrant
{
    public function getIdentifier(): string
    {
        return 'refresh_token';
    }

    public function respondToAccessTokenRequest(Request $request): array
    {
        $client = $this->validateClient($request);

        $rawRefreshToken = $request->getBodyParam('refresh_token', '');
        if (empty($rawRefreshToken)) {
            throw new InvalidRequestException('Missing refresh_token.');
        }

        /** @var \baha2odeh\yii2oauth\models\OAuthRefreshToken $refreshTokenModelClass */
        $refreshTokenModelClass = $this->refreshTokenModelClass;
        $refreshToken = $refreshTokenModelClass::findByRawToken($rawRefreshToken);

        if ($refreshToken === null) {
            throw new InvalidGrantException('Refresh token is invalid or expired.');
        }

        // Load the old access token to get user/scopes
        /** @var \baha2odeh\yii2oauth\models\OAuthAccessToken $accessTokenModelClass */
        $accessTokenModelClass = $this->accessTokenModelClass;
        $oldAccessToken = $accessTokenModelClass::find()
            ->where(['id' => $refreshToken->getAccessTokenId()])
            ->one();

        if ($oldAccessToken === null) {
            throw new InvalidGrantException('Associated access token not found.');
        }

        if ($oldAccessToken->getClientId() !== $client->getIdentifier()) {
            throw new InvalidGrantException('Refresh token was not issued to this client.');
        }

        // Requested scope must be a subset of the original
        $requestedScopeStr = $request->getBodyParam('scope', '');
        if (!empty($requestedScopeStr)) {
            $requested = array_filter(array_map('trim', explode(' ', $requestedScopeStr)));
            $original = $oldAccessToken->getScopes();
            foreach ($requested as $scope) {
                if (!in_array($scope, $original, true)) {
                    throw new InvalidScopeException(
                        "Scope '{$scope}' was not granted in the original token."
                    );
                }
            }
            $scopes = $requested;
        } else {
            $scopes = $oldAccessToken->getScopes();
        }

        // Revoke old tokens (access_token id column already holds the hash)
        $refreshTokenModelClass::revokeByRawToken($rawRefreshToken);
        $accessTokenModelClass::updateAll(['revoked' => 1], ['id' => $oldAccessToken->id]);

        // Issue new pair
        $newAccessToken = $this->issueAccessToken($client, $oldAccessToken->getUserId(), $scopes, $this->accessTokenTtl);
        $newRefreshToken = $this->issueRefreshToken($newAccessToken, $this->refreshTokenTtl);

        return $this->buildTokenResponse($newAccessToken, $newRefreshToken, $this->accessTokenTtl);
    }
}
