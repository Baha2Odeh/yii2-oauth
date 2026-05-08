<?php

namespace baha2odeh\yii2oauth\controllers;

use baha2odeh\yii2oauth\filters\BearerTokenAuth;
use yii\web\Controller;

/**
 * Default controller for the userinfo endpoint.
 * Out-of-box: handles GET/POST /oauth/userinfo via UserinfoAction.
 *
 * To use your own controller instead:
 * 'controllerMap' => ['userinfo' => \app\controllers\MyUserinfoController::class]
 */
class DefaultUserinfoController extends Controller
{
    public function behaviors(): array
    {
        return [
            'oauth' => BearerTokenAuth::class,
        ];
    }

    public function actions(): array
    {
        return [
            'index' => \baha2odeh\yii2oauth\actions\UserinfoAction::class,
        ];
    }
}
