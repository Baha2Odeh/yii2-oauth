<?php

namespace baha2odeh\yii2oauth\grants;

use baha2odeh\yii2oauth\exceptions\InvalidGrantException;
use baha2odeh\yii2oauth\exceptions\InvalidRequestException;
use baha2odeh\yii2oauth\models\OAuthAuthCode;
use baha2odeh\yii2oauth\services\TokenGenerator;
use yii\web\Request;

class AuthorizationCodeGrant extends AbstractGrant
{
    protected string $authCodeModelClass;
    protected int $authCodeTtl;
    protected bool $requirePkce = false;
    protected array $allowedPkceMethods = ['S256', 'plain'];

    public function getIdentifier(): string
    {
        return 'authorization_code';
    }

    public function canRespondToAuthorizationRequest(Request $request): bool
    {
        return $request->get('response_type') === 'code';
    }

    public function validateAuthorizationRequest(Request $request): array
    {
        $clientId = $request->get('client_id', '');
        if (empty($clientId)) {
            throw new InvalidRequestException('Missing client_id.');
        }

        /** @var \baha2odeh\yii2oauth\models\OAuthClient $clientModelClass */
        $clientModelClass = $this->clientModelClass;
        $client = $clientModelClass::findActive($clientId);

        if ($client === null) {
            throw new InvalidRequestException('Unknown or inactive client.');
        }

        if (!in_array('authorization_code', $client->getAllowedGrantTypes(), true)) {
            throw new \baha2odeh\yii2oauth\exceptions\UnauthorizedClientException(
                'Client is not authorized for the authorization_code grant.'
            );
        }

        // Validate redirect_uri
        $redirectUri = $request->get('redirect_uri', '');
        if (empty($redirectUri)) {
            $allowed = $client->getRedirectUris();
            if (count($allowed) === 1) {
                $redirectUri = $allowed[0];
            } else {
                throw new InvalidRequestException('Missing redirect_uri.');
            }
        } elseif (!in_array($redirectUri, $client->getRedirectUris(), true)) {
            throw new InvalidRequestException('Invalid redirect_uri.');
        }

        // Validate scopes
        $scopes = $this->validateScopes($request->get('scope', ''), $client);

        // PKCE
        $codeChallenge = $request->get('code_challenge');
        $codeChallengeMethod = $request->get('code_challenge_method', 'S256');

        $pkceRequired = $this->requirePkce || $client->requiresPkce();

        if ($pkceRequired && empty($codeChallenge)) {
            throw new InvalidRequestException('code_challenge is required for this client.');
        }

        if (!empty($codeChallenge)) {
            if (!in_array($codeChallengeMethod, $this->allowedPkceMethods, true)) {
                throw new InvalidRequestException(
                    'Unsupported code_challenge_method. Allowed: ' . implode(', ', $this->allowedPkceMethods)
                );
            }
        }

        return [
            'client'                => $client,
            'redirect_uri'          => $redirectUri,
            'scopes'                => $scopes,
            'state'                 => $request->get('state'),
            'code_challenge'        => !empty($codeChallenge) ? $codeChallenge : null,
            'code_challenge_method' => !empty($codeChallenge) ? $codeChallengeMethod : null,
        ];
    }

    public function completeAuthorizationRequest(array $authRequest, string $userId, bool $approved): string
    {
        $redirectUri = $authRequest['redirect_uri'];
        $state = $authRequest['state'] ?? null;

        if (!$approved) {
            return $this->buildRedirectUri($redirectUri, [
                'error'             => 'access_denied',
                'error_description' => 'The user denied the authorization request.',
                'state'             => $state,
            ]);
        }

        $raw = $this->tokenGenerator->generate();
        $hash = TokenGenerator::hash($raw);

        /** @var OAuthAuthCode $model */
        $model = new $this->authCodeModelClass();
        $model->id = $hash;
        $model->client_id = $authRequest['client']->getIdentifier();
        $model->user_id = $userId;
        $model->redirect_uri = $redirectUri;
        $model->scopes = json_encode($authRequest['scopes']);
        $model->code_challenge = $authRequest['code_challenge'];
        $model->code_challenge_method = $authRequest['code_challenge_method'];
        $model->revoked = 0;
        $model->expires_at = time() + $this->authCodeTtl;
        $model->created_at = time();

        if (!$model->save()) {
            throw new \RuntimeException('Failed to persist auth code: ' . json_encode($model->errors));
        }

        return $this->buildRedirectUri($redirectUri, array_filter([
            'code'  => $raw,
            'state' => $state,
        ]));
    }

    public function respondToAccessTokenRequest(Request $request): array
    {
        $client = $this->validateClient($request);

        $rawCode = $request->getBodyParam('code', '');
        if (empty($rawCode)) {
            throw new InvalidRequestException('Missing authorization code.');
        }

        /** @var \baha2odeh\yii2oauth\models\OAuthAuthCode $authCodeModelClass */
        $authCodeModelClass = $this->authCodeModelClass;
        $authCode = $authCodeModelClass::findByRawCode($rawCode);

        if ($authCode === null) {
            throw new InvalidGrantException('Authorization code is invalid or expired.');
        }

        if ($authCode->getClientId() !== $client->getIdentifier()) {
            throw new InvalidGrantException('Authorization code was not issued to this client.');
        }

        $redirectUri = $request->getBodyParam('redirect_uri', '');
        if (!empty($redirectUri) && $redirectUri !== $authCode->getRedirectUri()) {
            throw new InvalidGrantException('redirect_uri mismatch.');
        }

        // Validate PKCE if the code has a challenge stored
        if ($authCode->getCodeChallenge() !== null) {
            $codeVerifier = $request->getBodyParam('code_verifier', '');
            if (empty($codeVerifier)) {
                throw new InvalidRequestException('Missing code_verifier.');
            }
            $this->verifyPkce($codeVerifier, $authCode->getCodeChallenge(), $authCode->getCodeChallengeMethod() ?? 'S256');
        }

        // Revoke auth code (single-use)
        $authCodeModelClass::revokeByRawCode($rawCode);

        $accessToken = $this->issueAccessToken($client, $authCode->getUserId(), $authCode->getScopes(), $this->accessTokenTtl);
        $refreshToken = $this->issueRefreshToken($accessToken, $this->refreshTokenTtl);

        return $this->buildTokenResponse($accessToken, $refreshToken, $this->accessTokenTtl);
    }

    private function verifyPkce(string $verifier, string $challenge, string $method): void
    {
        if ($method === 'S256') {
            $computed = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        } else {
            $computed = $verifier;
        }

        if (!hash_equals($computed, $challenge)) {
            throw new InvalidGrantException('PKCE verification failed.');
        }
    }

    private function buildRedirectUri(string $base, array $params): string
    {
        $params = array_filter($params, fn($v) => $v !== null && $v !== '');
        $separator = str_contains($base, '?') ? '&' : '?';
        return $base . $separator . http_build_query($params);
    }
}
