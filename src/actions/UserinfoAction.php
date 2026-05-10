<?php

namespace baha2odeh\yii2oauth\actions;

use baha2odeh\yii2oauth\OAuthModule;
use yii\base\Action;
use yii\web\Response;

/**
 * Standalone action: returns user claims for authenticated Bearer tokens.
 *
 * Attach to any controller alongside BearerTokenAuth filter:
 *
 * ```php
 * public function behaviors(): array
 * {
 *     return ['oauth' => ['class' => \baha2odeh\yii2oauth\filters\BearerTokenAuth::class]];
 * }
 *
 * public function actions(): array
 * {
 *     return ['userinfo' => \baha2odeh\yii2oauth\actions\UserinfoAction::class];
 * }
 * ```
 *
 * Requires the BearerTokenAuth filter (or equivalent) to have set `Yii::$app->params['oauth.token']`.
 */
class UserinfoAction extends Action
{
    /** OAuth module ID. */
    public string $moduleId = 'oauth';

    public function run(): Response
    {
        $response = \Yii::$app->response;
        $response->format = Response::FORMAT_JSON;

        $token = \Yii::$app->params['oauth.token'] ?? null;

        if ($token === null) {
            $response->setStatusCode(401);
            $response->getHeaders()->set('WWW-Authenticate', 'Bearer realm="oauth"');
            $response->data = [
                'error' => 'invalid_token',
                'error_description' => 'Bearer token is required.',
            ];
            return $response;
        }

        $userId = $token->getUserId();

        if ($userId === null) {
            $response->setStatusCode(400);
            $response->data = [
                'error' => 'invalid_request',
                'error_description' => 'This token is not associated with a user.',
            ];
            return $response;
        }

        /** @var OAuthModule $module */
        $module = \Yii::$app->getModule($this->moduleId);
        $userModelClass = $module->userModelClass;

        if (empty($userModelClass)) {
            $response->setStatusCode(500);
            $response->data = ['error' => 'server_error', 'error_description' => 'userModelClass is not configured.'];
            return $response;
        }

        $user = $userModelClass::findIdentity($userId);

        if ($user === null) {
            $response->setStatusCode(404);
            $response->data = ['error' => 'not_found', 'error_description' => 'User not found.'];
            return $response;
        }

        $claims = method_exists($user, 'getClaims') ? $user->getClaims($token->getScopes()) : [];
        $response->data = array_merge(['sub' => (string) $userId], $claims);

        return $response;
    }
}
