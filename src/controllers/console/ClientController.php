<?php

namespace baha2odeh\yii2oauth\controllers\console;

use baha2odeh\yii2oauth\models\OAuthClient;
use baha2odeh\yii2oauth\OAuthModule;
use yii\console\Controller;
use yii\console\ExitCode;
use yii\helpers\Console;

/**
 * Manages OAuth2 clients and scopes.
 *
 * Usage:
 *   yii oauth/client/create --name="My App" --redirect-uris="https://app.com/cb"
 *   yii oauth/client/list
 *   yii oauth/client/delete <client_id>
 *   yii oauth/client/scopes
 *   yii oauth/client/purge-tokens
 */
class ClientController extends Controller
{
    public $defaultAction = 'list';

    /** OAuth module ID */
    public string $moduleId = 'oauth';

    // Create options
    public string $name = '';
    public string $redirectUris = '';
    public string $grantTypes = 'authorization_code,refresh_token';
    public string $scopes = '';
    public int $confidential = 1;
    public ?int $requirePkce = 0;

    public function options($actionId): array
    {
        $base = parent::options($actionId);

        return match ($actionId) {
            'create' => array_merge($base, ['name', 'redirectUris', 'grantTypes', 'scopes', 'confidential', 'requirePkce']),
            default => $base,
        };
    }

    public function optionAliases(): array
    {
        return array_merge(parent::optionAliases(), [
            'n' => 'name',
            'r' => 'redirectUris',
            'g' => 'grantTypes',
            's' => 'scopes',
            'c' => 'confidential',
        ]);
    }

    /**
     * Create a new OAuth2 client.
     *
     * Options:
     *   --name            Display name (required)
     *   --redirect-uris   Space or comma-separated redirect URIs (required for auth code)
     *   --grant-types     Comma-separated grant types (default: authorization_code,refresh_token)
     *   --scopes          Comma-separated allowed scopes
     *   --confidential    1 = confidential (default), 0 = public
     */
    public function actionCreate(): int
    {
        if (empty($this->name)) {
            $this->stderr("Error: --name is required.\n", Console::FG_RED);
            return ExitCode::USAGE;
        }

        $module = $this->getModule();
        $clientModelClass = $module->clientModelClass;

        $clientId = $this->generateId();
        $rawSecret = null;
        $hashedSecret = null;

        if ($this->confidential) {
            $rawSecret = bin2hex(random_bytes(32));
            $hashedSecret = \Yii::$app->security->generatePasswordHash($rawSecret);
        }

        $uriList = array_filter(array_map('trim', preg_split('/[\s,]+/', $this->redirectUris)));

        /** @var OAuthClient $client */
        $client = new $clientModelClass();
        $client->id = $clientId;
        $client->name = $this->name;
        $client->secret = $hashedSecret;
        $client->redirect_uris = json_encode(array_values($uriList));
        $client->grant_types = $this->grantTypes;
        $client->scopes = $this->scopes ?: null;
        $client->is_confidential = (int) $this->confidential;
        $client->is_active = 1;
        $client->require_pkce = $this->requirePkce ?? 0;

        if (!$client->save()) {
            $this->stderr("Failed to create client:\n", Console::FG_RED);
            foreach ($client->errors as $field => $errors) {
                foreach ($errors as $error) {
                    $this->stderr("  {$field}: {$error}\n", Console::FG_RED);
                }
            }
            return ExitCode::UNSPECIFIED_ERROR;
        }

        $this->stdout("\nClient created successfully!\n\n", Console::FG_GREEN, Console::BOLD);
        $this->stdout("Client ID:     {$clientId}\n");

        if ($rawSecret !== null) {
            $this->stdout("Client Secret: {$rawSecret}\n", Console::FG_YELLOW);
            $this->stdout("(Save the secret now — it cannot be retrieved again.)\n\n", Console::FG_YELLOW);
        } else {
            $this->stdout("Client Type:   Public (no secret)\n");
        }

        return ExitCode::OK;
    }

    /**
     * List all OAuth2 clients.
     */
    public function actionList(): int
    {
        $module = $this->getModule();
        $clientModelClass = $module->clientModelClass;

        $clients = $clientModelClass::find()->orderBy('created_at DESC')->all();

        if (empty($clients)) {
            $this->stdout("No clients registered.\n");
            return ExitCode::OK;
        }

        $this->stdout(str_pad('ID', 22).str_pad('Name', 30).str_pad('Grant Types', 40)."Active\n", Console::BOLD);
        $this->stdout(str_repeat('-', 100)."\n");

        foreach ($clients as $client) {
            $active = $client->is_active ? 'Yes' : 'No';
            $this->stdout(
                str_pad($client->id, 22).
                str_pad(mb_substr($client->name, 0, 28), 30).
                str_pad($client->grant_types, 40).
                $active."\n"
            );
        }

        return ExitCode::OK;
    }

    /**
     * Delete a client and all associated tokens.
     *
     * @param  string  $clientId
     */
    public function actionDelete(string $clientId): int
    {
        $module = $this->getModule();
        $clientModelClass = $module->clientModelClass;

        $client = $clientModelClass::findOne($clientId);

        if ($client === null) {
            $this->stderr("Client '{$clientId}' not found.\n", Console::FG_RED);
            return ExitCode::DATAERR;
        }

        if (!$this->confirm("Delete client '{$client->name}' ({$clientId}) and all associated tokens?")) {
            $this->stdout("Aborted.\n");
            return ExitCode::OK;
        }

        // Cascade deletions
        $accessTokenModelClass = $module->accessTokenModelClass;
        $refreshTokenModelClass = $module->refreshTokenModelClass;
        $authCodeModelClass = $module->authCodeModelClass;

        $accessTokenModelClass::deleteAll(['client_id' => $clientId]);
        $refreshTokenModelClass::deleteAll([
            'access_token_id' => // refresh tokens linked indirectly
                array_column(
                    $accessTokenModelClass::find()->select('id')->where(['client_id' => $clientId])->asArray()->all(),
                    'id'
                ),
        ]);
        $authCodeModelClass::deleteAll(['client_id' => $clientId]);
        $client->delete();

        $this->stdout("Client deleted.\n", Console::FG_GREEN);

        return ExitCode::OK;
    }

    /**
     * Deactivate a client (reversible).
     *
     * @param  string  $clientId
     */
    public function actionDeactivate(string $clientId): int
    {
        return $this->setActive($clientId, 0);
    }

    /**
     * Activate a previously deactivated client.
     *
     * @param  string  $clientId
     */
    public function actionActivate(string $clientId): int
    {
        return $this->setActive($clientId, 1);
    }

    /**
     * Rotate a client's secret (confidential clients only).
     *
     * @param  string  $clientId
     */
    public function actionResetSecret(string $clientId): int
    {
        $module = $this->getModule();
        $clientModelClass = $module->clientModelClass;

        $client = $clientModelClass::findOne($clientId);

        if ($client === null) {
            $this->stderr("Client '{$clientId}' not found.\n", Console::FG_RED);
            return ExitCode::DATAERR;
        }

        if (!$client->is_confidential) {
            $this->stderr("Client '{$clientId}' is a public client and does not have a secret.\n", Console::FG_RED);
            return ExitCode::DATAERR;
        }

        $rawSecret = bin2hex(random_bytes(32));
        $client->secret = \Yii::$app->security->generatePasswordHash($rawSecret);

        if (!$client->save(false, ['secret', 'updated_at'])) {
            $this->stderr("Failed to update secret.\n", Console::FG_RED);
            return ExitCode::UNSPECIFIED_ERROR;
        }

        $this->stdout("New secret: {$rawSecret}\n", Console::FG_YELLOW);
        $this->stdout("(Save it now — it cannot be retrieved again.)\n", Console::FG_YELLOW);

        return ExitCode::OK;
    }

    /**
     * List all registered scopes.
     */
    public function actionScopes(): int
    {
        $module = $this->getModule();
        $scopeModelClass = $module->scopeModelClass;

        $scopes = $scopeModelClass::find()->orderBy('identifier ASC')->all();

        if (empty($scopes)) {
            $this->stdout("No scopes registered.\n");
            return ExitCode::OK;
        }

        $this->stdout(str_pad('Identifier', 25).str_pad('Description', 50)."Default\n", Console::BOLD);
        $this->stdout(str_repeat('-', 85)."\n");

        foreach ($scopes as $scope) {
            $this->stdout(
                str_pad($scope->identifier, 25).
                str_pad(mb_substr($scope->description ?? '', 0, 48), 50).
                ($scope->is_default ? 'Yes' : 'No')."\n"
            );
        }

        return ExitCode::OK;
    }

    /**
     * Register a new scope.
     *
     * @param  string  $identifier  Scope identifier, e.g. 'openid'
     * @param  string  $description  Human-readable description
     * @param  int  $default  1 = default scope, 0 = explicit only (default)
     */
    public function actionAddScope(string $identifier, string $description = '', int $default = 0): int
    {
        $module = $this->getModule();
        $scopeModelClass = $module->scopeModelClass;

        $existing = $scopeModelClass::findOne($identifier);

        if ($existing !== null) {
            $this->stderr("Scope '{$identifier}' already exists.\n", Console::FG_RED);
            return ExitCode::DATAERR;
        }

        $scope = new $scopeModelClass();
        $scope->identifier = $identifier;
        $scope->description = $description ?: null;
        $scope->is_default = $default;

        if (!$scope->save()) {
            $this->stderr("Failed to save scope: ".json_encode($scope->errors)."\n", Console::FG_RED);
            return ExitCode::UNSPECIFIED_ERROR;
        }

        $this->stdout("Scope '{$identifier}' registered.\n", Console::FG_GREEN);

        return ExitCode::OK;
    }

    /**
     * Delete expired tokens from all token tables (safe to run via cron).
     */
    public function actionPurgeTokens(): int
    {
        $module = $this->getModule();
        $now = time();

        $at = $module->accessTokenModelClass::deleteAll(['<', 'expires_at', $now]);
        $rt = $module->refreshTokenModelClass::deleteAll(['<', 'expires_at', $now]);
        $ac = $module->authCodeModelClass::deleteAll(['<', 'expires_at', $now]);

        $this->stdout("Purged: {$at} access tokens, {$rt} refresh tokens, {$ac} auth codes.\n", Console::FG_GREEN);

        return ExitCode::OK;
    }

    // ---- Helpers ----

    private function setActive(string $clientId, int $active): int
    {
        $module = $this->getModule();
        $clientModelClass = $module->clientModelClass;

        $client = $clientModelClass::findOne($clientId);

        if ($client === null) {
            $this->stderr("Client '{$clientId}' not found.\n", Console::FG_RED);
            return ExitCode::DATAERR;
        }

        $client->is_active = $active;

        if (!$client->save(false, ['is_active', 'updated_at'])) {
            $this->stderr("Failed to update client.\n", Console::FG_RED);
            return ExitCode::UNSPECIFIED_ERROR;
        }

        $label = $active ? 'activated' : 'deactivated';
        $this->stdout("Client '{$clientId}' {$label}.\n", Console::FG_GREEN);

        return ExitCode::OK;
    }

    private function generateId(): string
    {
        return bin2hex(random_bytes(16));
    }

    private function getModule(): OAuthModule
    {
        return \Yii::$app->getModule($this->moduleId);
    }
}
