<?php

namespace baha2odeh\yii2oauth\grants;

use baha2odeh\yii2oauth\exceptions\UnauthorizedClientException;
use yii\web\Request;

class ClientCredentialsGrant extends AbstractGrant
{
    public function getIdentifier(): string
    {
        return 'client_credentials';
    }

    public function respondToAccessTokenRequest(Request $request): array
    {
        $client = $this->validateClient($request);

        if (!$client->isConfidential()) {
            throw new UnauthorizedClientException('client_credentials grant requires a confidential client.');
        }

        $scopes = $this->validateScopes($request->getBodyParam('scope', ''), $client);
        $accessToken = $this->issueAccessToken($client, null, $scopes, $this->accessTokenTtl);

        return $this->buildTokenResponse($accessToken, null, $this->accessTokenTtl);
    }
}
