# yii2-oauth

A lightweight, extensible OAuth2 authorization server extension for Yii2.

![PHP](https://img.shields.io/badge/PHP-8.1%2B-blue)
![Yii2](https://img.shields.io/badge/Yii2-2.0.54-green)
[![CI](https://github.com/Baha2Odeh/yii2-oauth/actions/workflows/ci.yml/badge.svg)](https://github.com/Baha2Odeh/yii2-oauth/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## Features

- **Authorization Code** grant with optional **PKCE** (S256 and plain)
- **Client Credentials** grant
- **Password** grant
- **Refresh Token** grant
- Token storage via **ActiveRecord** — no abstraction layers, pure Yii2 style
- Any model class is **swappable** from module config
- **Custom grant types** via a simple interface
- **BearerTokenAuth** filter — attach to any controller
- **Standalone actions** — attach token/authorize/userinfo to your own controllers
- **Console commands** for client and scope management
- Single database migration — SQLite, MySQL, PostgreSQL compatible

---

## Requirements

- PHP 8.1+
- Yii2 2.0.54+

---

## Installation

```bash
composer require baha2odeh/yii2-oauth
```

Run the migration:

```bash
php yii migrate --migrationPath=@vendor/baha2odeh/yii2-oauth/migrations
```

---

## Quick Start

### 1. Configure the module

Add the module to your application config (`config/web.php`):

```php
'bootstrap' => ['oauth'],

'modules' => [
    'oauth' => [
        'class' => \baha2odeh\yii2oauth\OAuthModule::class,
        'userModelClass' => \app\models\User::class,  // your user AR class
    ],
],
```

The module self-registers these URL rules automatically — no `urlManager` changes needed:

| Method | URL                        | Description                       |
|--------|----------------------------|-----------------------------------|
| `GET`  | `/oauth/authorize`         | Authorization consent page        |
| `POST` | `/oauth/authorize/approve` | User approves or denies consent   |
| `POST` | `/oauth/token`             | Token exchange endpoint           |
| `GET`  | `/oauth/userinfo`          | Returns authenticated user claims |

### 2. Implement `UserEntityInterface` on your User model

```php
use baha2odeh\yii2oauth\contracts\entities\UserEntityInterface;

class User extends \yii\db\ActiveRecord implements UserEntityInterface
{
    // Required by UserEntityInterface
    public function getIdentifier(): string
    {
        return (string) $this->id;
    }

    public function getClaims(): array
    {
        return [
            'email' => $this->email,
            'name' => $this->username,
        ];
    }

    // Required by the password grant
    public static function findByCredentials(string $username, string $password): ?static
    {
        $user = static::findOne(['username' => $username]);
        if ($user && \Yii::$app->security->validatePassword($password, $user->password_hash)) {
            return $user;
        }
        return null;
    }

    // Required by the /userinfo endpoint (standard Yii2 IdentityInterface)
    public static function findIdentity($id): ?static
    {
        return static::findOne($id);
    }
}
```

### 3. Create a client

```bash
php yii oauth/client/create --name="My App" --redirect-uris="https://myapp.com/callback"
```

Output:

```
Client created successfully!

Client ID:     a3f1c8d2e09b4561
Client Secret: 7f3a1b9c2d4e5f6a...
(Save the secret now — it cannot be retrieved again.)
```

### 4. Test the token endpoint

```bash
# Client Credentials
curl -X POST https://your-app.com/oauth/token \
  -u "a3f1c8d2e09b4561:7f3a1b9c2d4e5f6a..." \
  -d "grant_type=client_credentials"
```

```json
{
  "access_token": "e3b0c44298fc1c149a...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": ""
}
```

---

## Grant Types

### Authorization Code (with optional PKCE)

The recommended grant for web and mobile apps.

#### Step 1 — Redirect the user

```
GET /oauth/authorize
  ?response_type=code
  &client_id=YOUR_CLIENT_ID
  &redirect_uri=https://your-app.com/callback
  &scope=openid profile
  &state=RANDOM_STATE
  &code_challenge=PKCE_CHALLENGE        (optional, required for public clients with require_pkce=1)
  &code_challenge_method=S256           (S256 or plain, defaults to S256)
```

The user sees the consent page and approves or denies the request.
On approval, the server redirects back:

```
https://your-app.com/callback?code=AUTH_CODE&state=RANDOM_STATE
```

#### Step 2 — Exchange the code for tokens

```bash
curl -X POST https://your-app.com/oauth/token \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "redirect_uri=https://your-app.com/callback" \
  -d "code_verifier=PKCE_VERIFIER"    # if PKCE was used
```

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "scope": "openid profile"
}
```

#### PKCE Code Challenge Generation (PHP example)

```php
$verifier  = bin2hex(random_bytes(32));
$challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
// Store $verifier in session; send $challenge in the /authorize request
```

---

### Client Credentials

For machine-to-machine access. Confidential clients only.

```bash
curl -X POST https://your-app.com/oauth/token \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=api:read"
```

---

### Password

Directly exchange user credentials for tokens. Requires the `userModelClass` to implement `findByCredentials()`.

```bash
curl -X POST https://your-app.com/oauth/token \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -d "grant_type=password" \
  -d "username=alice@example.com" \
  -d "password=secret" \
  -d "scope=profile"
```

---

### Refresh Token

Exchange a refresh token for a new access + refresh token pair. Old tokens are revoked immediately.

```bash
curl -X POST https://your-app.com/oauth/token \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=REFRESH_TOKEN" \
  -d "scope=profile"    # optional — must be a subset of the original scope
```

---

## UserInfo Endpoint

Returns the authenticated user's claims. Requires a valid Bearer token.

```bash
curl https://your-app.com/oauth/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

```json
{
  "sub": "42",
  "email": "alice@example.com",
  "name": "alice"
}
```

The claims come from `UserEntityInterface::getClaims()` on your user model.

---

## Console Commands

### Client Management

```bash
# Create a confidential client
php yii oauth/client/create \
  --name="My App" \
  --redirect-uris="https://app.com/cb" \
  --grant-types="authorization_code,refresh_token" \
  --scopes="openid profile email" \
  --confidential=1

# Create a public client (SPA/mobile)
php yii oauth/client/create \
  --name="My SPA" \
  --redirect-uris="https://app.com/cb" \
  --grant-types="authorization_code,refresh_token" \
  --confidential=0

# List all clients
php yii oauth/client/list

# Deactivate (reversible)
php yii oauth/client/deactivate CLIENT_ID

# Re-activate
php yii oauth/client/activate CLIENT_ID

# Permanently delete (cascades tokens and auth codes)
php yii oauth/client/delete CLIENT_ID

# Rotate secret (prints new secret once)
php yii oauth/client/reset-secret CLIENT_ID
```

### Scope Management

```bash
# List registered scopes
php yii oauth/client/scopes

# Register a scope
php yii oauth/client/add-scope openid "OpenID Connect" --default=1
php yii oauth/client/add-scope profile "User profile"
php yii oauth/client/add-scope email "Email address"
```

### Maintenance

```bash
# Purge expired tokens (run via cron)
php yii oauth/client/purge-tokens
```

Recommended cron entry:

```cron
0 * * * * /path/to/yii oauth/client/purge-tokens >> /dev/null 2>&1
```

---

## Protecting Your Routes

### Using the BearerTokenAuth filter

Attach the filter to any controller or action:

```php
use baha2odeh\yii2oauth\filters\BearerTokenAuth;

class ApiController extends \yii\rest\Controller
{
    public function behaviors(): array
    {
        return array_merge(parent::behaviors(), [
            'oauth' => [
                'class' => BearerTokenAuth::class,
                'moduleId' => 'oauth',   // matches your module key, default 'oauth'
                'optional' => false,     // true = let unauthenticated requests through
            ],
        ]);
    }

    public function actionProfile(): array
    {
        // Access the validated token
        $token = \Yii::$app->params['oauth.token'];

        return [
            'user_id' => $token->getUserId(),
            'scopes' => $token->getScopes(),
        ];
    }
}
```

When a token is invalid or missing, the filter returns:

```json
HTTP 401
WWW-Authenticate: Bearer realm="oauth"

{"error": "invalid_token", "error_description": "..."}
```

---

## Attaching Actions to Your Own Controllers

Instead of the default controllers, you can attach the standalone actions to any existing controller:

```php
use baha2odeh\yii2oauth\actions\AuthorizeAction;
use baha2odeh\yii2oauth\actions\TokenAction;
use baha2odeh\yii2oauth\actions\UserinfoAction;
use baha2odeh\yii2oauth\filters\BearerTokenAuth;

class OAuthController extends \yii\web\Controller
{
    public $enableCsrfValidation = false; // required for token endpoint

    public function behaviors(): array
    {
        return [
            'bearer' => [
                'class' => BearerTokenAuth::class,
                'only' => ['userinfo'],
            ],
        ];
    }

    public function actions(): array
    {
        return [
            'token' => TokenAction::class,
            'authorize' => [
                'class' => AuthorizeAction::class,
                'viewFile' => '@app/views/oauth/authorize', // override the consent view
                'loginUrl' => ['/site/login'],
            ],
            'userinfo' => UserinfoAction::class,
        ];
    }
}
```

---

## Full Configuration Reference

```php
'modules' => [
        'oauth' => [
            'class' => \baha2odeh\yii2oauth\OAuthModule::class,

            // ---- Required ----
            'userModelClass' => \app\models\User::class,

            // ---- Model overrides (swap any AR class) ----
            'clientModelClass' => \app\models\OAuthClient::class,
            'accessTokenModelClass' => \baha2odeh\yii2oauth\models\OAuthAccessToken::class,
            'refreshTokenModelClass' => \baha2odeh\yii2oauth\models\OAuthRefreshToken::class,
            'authCodeModelClass' => \baha2odeh\yii2oauth\models\OAuthAuthCode::class,
            'scopeModelClass' => \baha2odeh\yii2oauth\models\OAuthScope::class,

            // ---- Enabled grants ----
            'enabledGrants' => [
                'authorization_code',
                'client_credentials',
                'password',
                'refresh_token',
            ],

            // ---- Token TTLs (seconds) ----
            'accessTokenTtl' => 3600,       // 1 hour
            'refreshTokenTtl' => 2592000,    // 30 days
            'authCodeTtl' => 600,        // 10 minutes

            // ---- Token entropy ----
            'tokenBytes' => 32,              // 32 bytes → 64-char hex token

            // ---- PKCE ----
            // false: PKCE is optional globally; per-client require_pkce column overrides
            // true:  PKCE required for every client
            'requirePkce' => false,
            'allowedPkceMethods' => ['S256', 'plain'],

            // ---- Custom grants ----
            'customGrants' => [
                'device_code' => \app\oauth\DeviceCodeGrant::class,
            ],
        ],
],
```

---

## Customization

### Extending a Model

```php
namespace app\models;

use baha2odeh\yii2oauth\models\OAuthClient as BaseClient;

class OAuthClient extends BaseClient
{
    // Add extra scopes validation, multi-tenancy, etc.
    public static function validateCredentials(string $clientId, ?string $secret, string $grantType): ?static
    {
        $client = parent::validateCredentials($clientId, $secret, $grantType);
        // Additional checks (e.g. tenant isolation)
        return $client;
    }
}
```

Register the extended model:

```php
'clientModelClass' => \app\models\OAuthClient::class,
```

### Writing a Custom Grant

```php
namespace app\oauth;

use baha2odeh\yii2oauth\grants\AbstractGrant;
use yii\web\Request;

class DeviceCodeGrant extends AbstractGrant
{
    public function getIdentifier(): string
    {
        return 'urn:ietf:params:oauth:grant-type:device_code';
    }

    public function respondToAccessTokenRequest(Request $request): array
    {
        $client = $this->validateClient($request);
        $deviceCode = $request->getBodyParam('device_code', '');

        // ... your device code validation logic ...

        $scopes = $this->validateScopes('', $client);
        $token = $this->issueAccessToken($client, null, $scopes, $this->accessTokenTtl);

        return $this->buildTokenResponse($token, null, $this->accessTokenTtl);
    }
}
```

Register it in config:

```php
'customGrants' => [
    'urn:ietf:params:oauth:grant-type:device_code' => \app\oauth\DeviceCodeGrant::class,
],
```

### Overriding the Consent View

Create a view at any path and set it on the action:

```php
// In your controller
'authorize' => [
    'class'    => \baha2odeh\yii2oauth\actions\AuthorizeAction::class,
    'viewFile' => '@app/views/oauth/consent',
],
```

Available variables in the view:

| Variable  | Type                    | Description                             |
|-----------|-------------------------|-----------------------------------------|
| `$client` | `ClientEntityInterface` | The requesting client                   |
| `$scopes` | `array<string, string>` | `identifier => description` pairs       |
| `$state`  | `string\|null`          | The state parameter from the request    |
| `$action` | `AuthorizeAction`       | The action instance (access `moduleId`) |

Minimal consent view example:

```php
<?php
use yii\helpers\Html;
?>
<h2><?= Html::encode($client->getName()) ?> wants access</h2>
<ul>
    <?php foreach ($scopes as $id => $desc): ?>
        <li><?= Html::encode($desc) ?></li>
    <?php endforeach; ?>
</ul>
<?php $form = \yii\widgets\ActiveForm::begin(); ?>
    <?= Html::hiddenInput('state', $state) ?>
    <?= Html::submitButton('Allow', ['name' => 'approved', 'value' => '1']) ?>
    <?= Html::submitButton('Deny',  ['name' => 'approved', 'value' => '0']) ?>
<?php \yii\widgets\ActiveForm::end(); ?>
```

---

## Database Tables

| Table                  | Description                            |
|------------------------|----------------------------------------|
| `oauth_clients`        | Registered OAuth2 clients              |
| `oauth_scopes`         | Available permission scopes            |
| `oauth_access_tokens`  | Issued access tokens (SHA-256 hashed)  |
| `oauth_refresh_tokens` | Refresh tokens linked to access tokens |
| `oauth_auth_codes`     | Authorization codes (single-use)       |

Token values are **never stored in plain text**. The SHA-256 hash is stored; the raw value is returned to the client
once and never held server-side.

---

## Security Notes

- **Client secrets** are stored as bcrypt hashes (`Yii::$app->security->generatePasswordHash`).
- **Tokens** are stored as SHA-256 hashes. Compromise of the database does not expose usable tokens.
- **Authorization codes** are single-use and expire in 10 minutes by default.
- **PKCE** is strongly recommended for public clients (SPAs, mobile apps). Enable it per-client with `require_pkce = 1`
  or globally with `'requirePkce' => true`.
- The token endpoint sets `Cache-Control: no-store` and `Pragma: no-cache` on every response.
- CSRF validation is disabled only on the token endpoint (OAuth2 spec requirement).

---

## Running Tests

```bash
composer install
vendor/bin/phpunit
```

Tests use an **in-memory SQLite database** — no external dependencies required.

---

## License

MIT © [Baha2Odeh](https://github.com/Baha2Odeh)
