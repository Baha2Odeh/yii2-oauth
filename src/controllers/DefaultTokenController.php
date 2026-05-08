<?php

namespace baha2odeh\yii2oauth\controllers;

use yii\web\Controller;

/**
 * Default controller for the token endpoint.
 * Out-of-box: handles POST /oauth/token via TokenAction.
 *
 * To use your own controller instead, override controllerMap in the module config:
 * 'controllerMap' => ['token' => \app\controllers\MyTokenController::class]
 */
class DefaultTokenController extends Controller
{
    public $enableCsrfValidation = false;

    public function actions(): array
    {
        return [
            'token' => \baha2odeh\yii2oauth\actions\TokenAction::class,
        ];
    }
}
