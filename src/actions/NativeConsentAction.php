<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\actions;

use baha2odeh\yii2oauth\exceptions\OAuthException;
use baha2odeh\yii2oauth\grants\AuthorizationCodeGrant;
use baha2odeh\yii2oauth\OAuthModule;
use baha2odeh\yii2oauth\services\TokenGenerator;
use yii\web\Request;
use yii\web\Response;
use yii\web\UnauthorizedHttpException;
/**
 * Standalone action for native App-to-App SSO (App B <- App A) without a WebView.
 *
 * ```php
 * public function actions(): array
 * {
 *     return [
 *         'native-consent' => [
 *             'class'       => \baha2odeh\yii2oauth\actions\NativeConsentAction::class,
 *             'authCodeTtl' => 60, // short-lived, native codes are exchanged immediately
 *         ],
 *     ];
 * }
 * ```
 *
 * Expected JSON body (Content-Type: application/json):
 * {
 *   "client_id": "app_b_client_id",
 *   "redirect_uri": "appb://callback",
 *   "response_type": "code",
 *   "code_challenge": "XYZ123...",
 *   "code_challenge_method": "S256",
 *   "scopes": "profile email"
 * }
 */
class NativeConsentAction extends \yii\base\Action
{
    /** OAuth module ID. */
    public string $moduleId = 'oauth';

    /**
     * Auth-code TTL (seconds) for this endpoint. Native codes are redeemed immediately,
     * so keep this short. When null, the module's `authCodeTtl` is used.
     */
    public ?int $authCodeTtl = 60;

    public function run(): Response
    {
        $response = \Yii::$app->response;
        $response->format = Response::FORMAT_JSON;

        $userId = \Yii::$app->user->id;
        if ($userId === null) {
            throw new UnauthorizedHttpException('A valid, user-bound access token is required');
        }

        $grant = $this->buildGrant();

        try {
            // The grant reads authorization params from the query string; the native client
            // sends them as a JSON body, so mirror them into a synthetic request.
            $authRequest = $grant->validateAuthorizationRequest($this->buildAuthorizationRequest());
            $authRequest['grant_type'] = 'authorization_code';

            $redirectUri = $grant->completeAuthorizationRequest($authRequest, $userId, true);
        } catch (OAuthException $e) {
            $response->setStatusCode($e->getHttpStatusCode());
            return $this->fail($response, $e->getErrorCode(), $e->getMessage());
        }

        $code = $this->extractCode($redirectUri);
        if ($code === null) {
            $response->setStatusCode(500);
            return $this->fail($response, 'server_error', 'Failed to generate authorization code.');
        }

        $response->data = [
            'success' => true,
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'expires_in' => $this->authCodeTtl ?? $this->getModule()->authCodeTtl,
        ];

        return $response;
    }

    /**
     * Build a request whose query params carry the authorization parameters read from
     * the JSON body, so the grant's existing query-based validation can be reused as-is.
     */
    private function buildAuthorizationRequest(): Request
    {
        $body = \Yii::$app->request->getBodyParams();

        $req = new Request();
        $req->setQueryParams([
            'response_type' => $body['response_type'] ?? 'code',
            'client_id' => $body['client_id'] ?? '',
            'redirect_uri' => $body['redirect_uri'] ?? '',
            // Accept both `scopes` (this endpoint's contract) and `scope` (OAuth spelling).
            'scope' => $body['scopes'] ?? $body['scope'] ?? '',
            'state' => $body['state'] ?? null,
            'code_challenge' => $body['code_challenge'] ?? null,
            'code_challenge_method' => $body['code_challenge_method'] ?? 'S256',
        ]);

        return $req;
    }

    /**
     * Build a dedicated authorization-code grant mirroring the module wiring, with this
     * action's short auth-code TTL applied.
     */
    private function buildGrant(): AuthorizationCodeGrant
    {
        $module = $this->getModule();

        return new AuthorizationCodeGrant([
            'clientModelClass' => $module->clientModelClass,
            'accessTokenModelClass' => $module->accessTokenModelClass,
            'refreshTokenModelClass' => $module->refreshTokenModelClass,
            'scopeModelClass' => $module->scopeModelClass,
            'authCodeModelClass' => $module->authCodeModelClass,
            'tokenGenerator' => new TokenGenerator($module->tokenBytes),
            'accessTokenTtl' => $module->accessTokenTtl,
            'refreshTokenTtl' => $module->refreshTokenTtl,
            'authCodeTtl' => $this->authCodeTtl ?? $module->authCodeTtl,
            'requirePkce' => $module->requirePkce,
            'allowedPkceMethods' => $module->allowedPkceMethods,
        ]);
    }

    /** Pull the `code` query param out of the grant's redirect URI. */
    private function extractCode(string $redirectUri): ?string
    {
        $query = parse_url($redirectUri, PHP_URL_QUERY);
        if (!is_string($query) || $query === '') {
            return null;
        }

        parse_str($query, $params);
        $code = $params['code'] ?? null;

        return is_string($code) && $code !== '' ? $code : null;
    }

    private function getModule(): OAuthModule
    {
        /** @var OAuthModule $module */
        $module = \Yii::$app->getModule($this->moduleId);
        return $module;
    }

    private function fail(Response $response, string $error, string $description): Response
    {
        $response->data = [
            'success' => false,
            'error' => $error,
            'error_description' => $description,
        ];
        return $response;
    }
}