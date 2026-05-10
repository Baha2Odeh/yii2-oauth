<?php

namespace baha2odeh\yii2oauth\models;

use baha2odeh\yii2oauth\contracts\entities\ClientEntityInterface;
use yii\db\ActiveRecord;

/**
 * @property string $id
 * @property string $name
 * @property string|null $secret
 * @property string $redirect_uris  JSON array
 * @property string $grant_types    comma-separated
 * @property string|null $scopes         comma-separated
 * @property int $is_confidential
 * @property int $is_active
 * @property int $require_pkce
 * @property int|null $user_id
 * @property int $created_at
 * @property int $updated_at
 */
class OAuthClient extends ActiveRecord implements ClientEntityInterface
{
    public static function tableName(): string
    {
        return '{{%oauth_clients}}';
    }

    public function rules(): array
    {
        return [
            [['id', 'name', 'redirect_uris', 'grant_types'], 'required'],
            [['id'], 'string', 'max' => 80],
            [['name'], 'string', 'max' => 255],
            [['secret'], 'string', 'max' => 255],
            [['redirect_uris', 'scopes'], 'string'],
            [['grant_types'], 'string', 'max' => 500],
            [['is_confidential', 'is_active', 'require_pkce'], 'boolean'],
            [['user_id'], 'integer'],
            [['secret', 'scopes', 'user_id'], 'default', 'value' => null],
        ];
    }

    public function behaviors(): array
    {
        return [
            \yii\behaviors\TimestampBehavior::class,
        ];
    }

    // ---- ClientEntityInterface ----

    public function getIdentifier(): string
    {
        return $this->id;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getRedirectUris(): array
    {
        return json_decode($this->redirect_uris, true) ?: [];
    }

    public function isConfidential(): bool
    {
        return (bool) $this->is_confidential;
    }

    public function isActive(): bool
    {
        return (bool) $this->is_active;
    }

    public function getAllowedGrantTypes(): array
    {
        return array_filter(array_map('trim', explode(',', $this->grant_types)));
    }

    public function getAllowedScopes(): array
    {
        if (empty($this->scopes)) {
            return [];
        }
        return array_filter(array_map('trim', explode(',', $this->scopes)));
    }

    public function requiresPkce(): bool
    {
        return (bool) $this->require_pkce;
    }

    // ---- Static finders ----

    public static function findActive(string $clientId): ?static
    {
        return static::find()
            ->where(['id' => $clientId, 'is_active' => 1])
            ->one();
    }

    /**
     * Find and validate a client by credentials and grant type.
     * For public clients pass $secret = null.
     */
    public static function validateCredentials(string $clientId, ?string $secret, string $grantType): ?static
    {
        $client = static::findActive($clientId);

        if ($client === null) {
            return null;
        }

        if (!in_array($grantType, $client->getAllowedGrantTypes(), true)) {
            return null;
        }

        if ($client->isConfidential()) {
            if ($secret === null || $client->secret === null) {
                return null;
            }
            if (!\Yii::$app->security->validatePassword($secret, $client->secret)) {
                return null;
            }
        }

        return $client;
    }
}
