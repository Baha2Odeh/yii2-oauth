<?php

namespace baha2odeh\yii2oauth;

use baha2odeh\yii2oauth\grants\AuthorizationCodeGrant;
use baha2odeh\yii2oauth\grants\ClientCredentialsGrant;
use baha2odeh\yii2oauth\grants\PasswordGrant;
use baha2odeh\yii2oauth\grants\RefreshTokenGrant;
use baha2odeh\yii2oauth\models\OAuthAccessToken;
use baha2odeh\yii2oauth\models\OAuthAuthCode;
use baha2odeh\yii2oauth\models\OAuthClient;
use baha2odeh\yii2oauth\models\OAuthRefreshToken;
use baha2odeh\yii2oauth\models\OAuthScope;
use baha2odeh\yii2oauth\services\AuthorizationServer;
use baha2odeh\yii2oauth\services\TokenGenerator;
use yii\base\Application;
use yii\base\BootstrapInterface;
use yii\base\Module;

class OAuthModule extends Module implements BootstrapInterface
{
    // ---- Model classes (override any to swap the AR model) ----

    public string $clientModelClass = OAuthClient::class;
    public string $accessTokenModelClass = OAuthAccessToken::class;
    public string $refreshTokenModelClass = OAuthRefreshToken::class;
    public string $authCodeModelClass = OAuthAuthCode::class;
    public string $scopeModelClass = OAuthScope::class;

    /**
     * App's user AR class. Must implement UserEntityInterface.
     * Required for the password grant and /userinfo endpoint.
     */
    public string $userModelClass = '';

    // ---- Enabled grants ----

    public array $enabledGrants = [
        'authorization_code',
        'client_credentials',
        'password',
        'refresh_token',
    ];

    /**
     * Custom grant classes keyed by grant identifier.
     * e.g. ['device_code' => \app\oauth\DeviceCodeGrant::class]
     * Custom grants are merged with enabled built-in grants.
     */
    public array $customGrants = [];

    // ---- Token TTLs (seconds) ----

    public int $accessTokenTtl = 3600;
    public int $refreshTokenTtl = 2592000;
    public int $authCodeTtl = 600;

    /** Token entropy in bytes (hex output = 2× bytes). */
    public int $tokenBytes = 32;

    // ---- PKCE ----

    /**
     * false = PKCE is optional (client may send it; server validates if present).
     * true  = PKCE required for all clients (per-client require_pkce column overrides per row).
     */
    public bool $requirePkce = false;

    public array $allowedPkceMethods = ['S256', 'plain'];

    // ---- Internals ----

    private ?AuthorizationServer $_authorizationServer = null;

    public function init(): void
    {
        parent::init();

        if (empty($this->controllerNamespace)) {
            $this->controllerNamespace = 'baha2odeh\yii2oauth\controllers';
        }

        $this->controllerMap = array_merge([
            'token'     => controllers\DefaultTokenController::class,
            'authorize' => controllers\DefaultAuthorizeController::class,
            'userinfo'  => controllers\DefaultUserinfoController::class,
        ], $this->controllerMap ?? []);
    }

    /**
     * Auto-registers URL rules and (for console apps) the client controller.
     */
    public function bootstrap($app): void
    {
        if ($app instanceof \yii\web\Application) {
            $app->getUrlManager()->addRules([
                [
                    'class'   => \yii\web\UrlRule::class,
                    'pattern' => $this->id . '/token',
                    'route'   => $this->id . '/token/token',
                    'verb'    => 'POST',
                ],
                [
                    'class'   => \yii\web\UrlRule::class,
                    'pattern' => $this->id . '/authorize',
                    'route'   => $this->id . '/authorize/index',
                ],
                [
                    'class'   => \yii\web\UrlRule::class,
                    'pattern' => $this->id . '/authorize/approve',
                    'route'   => $this->id . '/authorize/approve',
                    'verb'    => 'POST',
                ],
                [
                    'class'    => \yii\web\UrlRule::class,
                    'pattern'  => $this->id . '/userinfo',
                    'route'    => $this->id . '/userinfo/index',
                    'verb'     => ['GET', 'POST'],
                ],
            ], false);
        }

        if ($app instanceof \yii\console\Application) {
            $app->controllerMap[$this->id . '/client'] = [
                'class' => controllers\console\ClientController::class,
                'moduleId' => $this->id,
            ];
        }
    }

    /** Returns a lazily built, fully wired AuthorizationServer. */
    public function getAuthorizationServer(): AuthorizationServer
    {
        if ($this->_authorizationServer === null) {
            $this->_authorizationServer = $this->buildAuthorizationServer();
        }

        return $this->_authorizationServer;
    }

    private function buildAuthorizationServer(): AuthorizationServer
    {
        $server = new AuthorizationServer();
        $generator = new TokenGenerator($this->tokenBytes);

        $sharedConfig = [
            'clientModelClass'       => $this->clientModelClass,
            'accessTokenModelClass'  => $this->accessTokenModelClass,
            'refreshTokenModelClass' => $this->refreshTokenModelClass,
            'scopeModelClass'        => $this->scopeModelClass,
            'tokenGenerator'         => $generator,
            'accessTokenTtl'         => $this->accessTokenTtl,
            'refreshTokenTtl'        => $this->refreshTokenTtl,
        ];

        $builtInMap = [
            'authorization_code' => AuthorizationCodeGrant::class,
            'client_credentials' => ClientCredentialsGrant::class,
            'password'           => PasswordGrant::class,
            'refresh_token'      => RefreshTokenGrant::class,
        ];

        foreach ($this->enabledGrants as $grantId) {
            if (!isset($builtInMap[$grantId])) {
                continue;
            }

            $grantClass = $builtInMap[$grantId];
            $grantConfig = $sharedConfig;

            if ($grantId === 'authorization_code') {
                $grantConfig['authCodeModelClass'] = $this->authCodeModelClass;
                $grantConfig['authCodeTtl'] = $this->authCodeTtl;
                $grantConfig['requirePkce'] = $this->requirePkce;
                $grantConfig['allowedPkceMethods'] = $this->allowedPkceMethods;
            }

            if ($grantId === 'password') {
                $grantConfig['userModelClass'] = $this->userModelClass;
            }

            $server->registerGrant(new $grantClass($grantConfig));
        }

        // Custom grants
        foreach ($this->customGrants as $grantId => $grantClass) {
            $server->registerGrant(new $grantClass(array_merge($sharedConfig, [
                'authCodeModelClass' => $this->authCodeModelClass,
                'authCodeTtl'        => $this->authCodeTtl,
                'userModelClass'     => $this->userModelClass,
            ])));
        }

        return $server;
    }
}
