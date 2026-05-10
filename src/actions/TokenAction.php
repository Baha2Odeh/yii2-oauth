<?php

namespace baha2odeh\yii2oauth\actions;

use baha2odeh\yii2oauth\exceptions\OAuthException;
use baha2odeh\yii2oauth\OAuthModule;
use yii\base\Action;

/**
 * Standalone action: handles POST token requests.
 *
 * Attach to any controller:
 *
 * ```php
 * public function actions(): array
 * {
 *     return ['token' => \baha2odeh\yii2oauth\actions\TokenAction::class];
 * }
 * ```
 *
 * The host controller MUST disable CSRF validation for this action (or globally).
 */
class TokenAction extends Action
{
    /** OAuth module ID to resolve the authorization server from. */
    public string $moduleId = 'oauth';

    public function run(): \yii\web\Response
    {
        $response = \Yii::$app->response;
        $response->format = \yii\web\Response::FORMAT_JSON;
        $response->getHeaders()->set('Cache-Control', 'no-store');
        $response->getHeaders()->set('Pragma', 'no-cache');

        /** @var OAuthModule $module */
        $module = \Yii::$app->getModule($this->moduleId);

        try {
            $data = $module->getAuthorizationServer()->respondToAccessTokenRequest(\Yii::$app->request);
            $response->setStatusCode(200);
            $response->data = $data;
        } catch (OAuthException $e) {
            $response->setStatusCode($e->getHttpStatusCode());
            $response->data = [
                'error' => $e->getErrorCode(),
                'error_description' => $e->getMessage(),
            ];
        }

        return $response;
    }
}
