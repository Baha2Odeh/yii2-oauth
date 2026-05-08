<?php

namespace baha2odeh\yii2oauth\filters;

use baha2odeh\yii2oauth\OAuthModule;
use yii\base\ActionFilter;

/**
 * Action filter that authenticates requests via OAuth2 Bearer tokens.
 *
 * Attach to a controller or specific actions:
 *
 * ```php
 * public function behaviors(): array
 * {
 *     return [
 *         'oauth' => [
 *             'class' => BearerTokenAuth::class,
 *         ],
 *     ];
 * }
 * ```
 *
 * The resolved token entity is stored at `Yii::$app->params['oauth.token']`.
 */
class BearerTokenAuth extends ActionFilter
{
    /**
     * When true, a missing/invalid token sends a 401 response.
     * When false, the request proceeds and the token is simply not set.
     */
    public bool $optional = false;

    /**
     * OAuth module ID. Defaults to 'oauth'.
     * Change if you registered the module under a different key.
     */
    public string $moduleId = 'oauth';

    public function beforeAction($action): bool
    {
        $rawToken = $this->extractBearerToken(\Yii::$app->request);

        if ($rawToken === null) {
            if ($this->optional) {
                return true;
            }
            return $this->denyUnauthorized();
        }

        /** @var OAuthModule $module */
        $module = \Yii::$app->getModule($this->moduleId);
        $accessTokenModelClass = $module->accessTokenModelClass;

        $token = $accessTokenModelClass::findByRawToken($rawToken);

        if ($token === null) {
            if ($this->optional) {
                return true;
            }
            return $this->denyUnauthorized();
        }

        \Yii::$app->params['oauth.token'] = $token;

        return true;
    }

    private function extractBearerToken(\yii\web\Request $request): ?string
    {
        $authHeader = $request->getHeaders()->get('Authorization', '');
        if (str_starts_with($authHeader, 'Bearer ')) {
            $token = trim(substr($authHeader, 7));
            return $token !== '' ? $token : null;
        }

        // Fallback: access_token query/body param (RFC 6750 §2.3)
        $token = $request->get('access_token') ?? $request->getBodyParam('access_token');
        return $token ?: null;
    }

    private function denyUnauthorized(): bool
    {
        $response = \Yii::$app->response;
        $response->setStatusCode(401);
        $response->getHeaders()->set('WWW-Authenticate', 'Bearer realm="oauth"');
        $response->format = \yii\web\Response::FORMAT_JSON;
        $response->data = [
            'error'             => 'invalid_token',
            'error_description' => 'The access token provided is missing, invalid, or expired.',
        ];
        $response->send();

        return false;
    }
}
