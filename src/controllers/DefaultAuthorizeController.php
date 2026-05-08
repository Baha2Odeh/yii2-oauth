<?php

namespace baha2odeh\yii2oauth\controllers;

use yii\web\Controller;

/**
 * Default controller for the authorization endpoint.
 * Out-of-box: handles GET/POST /oauth/authorize via AuthorizeAction.
 *
 * To use your own controller (with your own layout) instead:
 * 'controllerMap' => ['authorize' => \app\controllers\MyAuthorizeController::class]
 */
class DefaultAuthorizeController extends Controller
{
    public function actions(): array
    {
        return [
            'index' => \baha2odeh\yii2oauth\actions\AuthorizeAction::class,
        ];
    }
}
