<?php

namespace baha2odeh\yii2oauth\actions;

use baha2odeh\yii2oauth\exceptions\OAuthException;
use baha2odeh\yii2oauth\models\OAuthAccessToken;
use baha2odeh\yii2oauth\OAuthModule;
use yii\base\Action;
use yii\web\Response;

/**
 * Standalone action: handles GET (show consent) and POST (approve/deny) authorization requests.
 *
 * Attach to any web controller:
 *
 * ```php
 * public function actions(): array
 * {
 *     return [
 *         'authorize' => [
 *             'class'    => \baha2odeh\yii2oauth\actions\AuthorizeAction::class,
 *             'viewFile' => '@app/views/oauth/authorize',  // optional override
 *             'loginUrl' => ['/site/login'],               // optional override
 *         ],
 *     ];
 * }
 * ```
 *
 * The action stores the validated auth request in the session under the key `oauth_auth_request`.
 */
class AuthorizeAction extends Action
{
    /** Path to the consent view. Defaults to the bundled view. */
    public string $viewFile = '@baha2odeh/yii2oauth/views/authorize/index';

    /** URL to redirect to when the user is not authenticated. */
    public string|array $loginUrl = ['/site/login'];

    /** OAuth module ID. */
    public string $moduleId = 'oauth';

    /** Session key used to persist the authorization request between GET and POST. */
    public string $sessionKey = 'oauth_auth_request';

    public function run(): string|Response
    {
        $request = \Yii::$app->request;

        if ($request->isPost) {
            return $this->handleApproval();
        }

        return $this->handleAuthorize();
    }

    private function handleAuthorize(): string|Response
    {
        /** @var OAuthModule $module */
        $module = \Yii::$app->getModule($this->moduleId);

        try {
            $authRequest = $module->getAuthorizationServer()->validateAuthorizationRequest(\Yii::$app->request);
            // Store grant type for dispatch during completeAuthorizationRequest
            $authRequest['grant_type'] = 'authorization_code';
        } catch (OAuthException $e) {
            return $this->renderError($e);
        }

        // If user is not logged in, redirect to login and come back
        if (\Yii::$app->user->isGuest) {
            \Yii::$app->user->loginRequired();
            return \Yii::$app->response;
        }

        // If user already approved this client+scopes, auto-approve (skip consent)
        $userId = (string) \Yii::$app->user->id;
        $clientId = $authRequest['client']->getIdentifier();
        if (OAuthAccessToken::hasActiveToken($userId, $clientId, $authRequest['scopes'])) {
            $authRequest['grant_type'] = 'authorization_code';
            try {
                $redirectUri = $module->getAuthorizationServer()->completeAuthorizationRequest(
                    $authRequest,
                    $userId,
                    true
                );
            } catch (OAuthException $e) {
                return $this->renderError($e);
            }
            return \Yii::$app->response->redirect($redirectUri);
        }

        // Store the auth request in session and show the consent form
        \Yii::$app->session->set($this->sessionKey, $authRequest);

        $scopes = [];
        foreach ($authRequest['scopes'] as $scopeId) {
            /** @var \baha2odeh\yii2oauth\models\OAuthScope $scopeModelClass */
            $scopeModelClass = $module->scopeModelClass;
            $scope = $scopeModelClass::findByIdentifier($scopeId);
            $scopes[$scopeId] = $scope?->getDescription() ?? $scopeId;
        }

        return $this->controller->render($this->viewFile, [
            'client'   => $authRequest['client'],
            'scopes'   => $scopes,
            'state'    => $authRequest['state'] ?? null,
            'action'   => $this,
        ]);
    }

    private function handleApproval(): Response
    {
        $authRequest = \Yii::$app->session->get($this->sessionKey);

        if ($authRequest === null) {
            \Yii::$app->response->setStatusCode(400);
            \Yii::$app->response->data = 'Authorization session expired. Please start again.';
            return \Yii::$app->response;
        }

        \Yii::$app->session->remove($this->sessionKey);

        $approved = (bool) \Yii::$app->request->post('approved', false);
        $userId = (string) \Yii::$app->user->id;

        /** @var OAuthModule $module */
        $module = \Yii::$app->getModule($this->moduleId);

        try {
            $redirectUri = $module->getAuthorizationServer()->completeAuthorizationRequest(
                $authRequest,
                $userId,
                $approved
            );
        } catch (OAuthException $e) {
            return $this->renderError($e);
        }

        return \Yii::$app->response->redirect($redirectUri);
    }

    private function renderError(OAuthException $e): Response
    {
        \Yii::$app->response->setStatusCode($e->getHttpStatusCode());
        \Yii::$app->response->format = \yii\web\Response::FORMAT_JSON;
        \Yii::$app->response->data = [
            'error'             => $e->getErrorCode(),
            'error_description' => $e->getMessage(),
        ];
        return \Yii::$app->response;
    }
}
