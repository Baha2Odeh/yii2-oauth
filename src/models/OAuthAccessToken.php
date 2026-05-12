<?php

namespace baha2odeh\yii2oauth\models;

use baha2odeh\yii2oauth\contracts\entities\AccessTokenEntityInterface;
use baha2odeh\yii2oauth\services\TokenGenerator;
use yii\db\ActiveRecord;

/**
 * @property string      $id          SHA-256 hash of raw token
 * @property string      $client_id
 * @property string|null $user_id
 * @property string|null $scopes      JSON array
 * @property int         $revoked
 * @property int         $expires_at
 * @property int         $created_at
 */
class OAuthAccessToken extends ActiveRecord implements AccessTokenEntityInterface
{
    /** Raw token — set after generation, never persisted. */
    private ?string $_rawToken = null;

    public static function tableName(): string
    {
        return '{{%oauth_access_tokens}}';
    }

    public function rules(): array
    {
        return [
            [['id', 'client_id', 'expires_at', 'created_at'], 'required'],
            [['id', 'client_id'], 'string', 'max' => 80],
            [['user_id'], 'string', 'max' => 255],
            [['scopes'], 'string'],
            [['revoked'], 'boolean'],
            [['expires_at', 'created_at'], 'integer'],
            [['user_id', 'scopes'], 'default', 'value' => null],
        ];
    }

    // ---- Raw token management ----

    public function setRawToken(string $raw): void
    {
        $this->_rawToken = $raw;
    }

    // ---- AccessTokenEntityInterface ----

    public function getIdentifier(): string
    {
        return $this->_rawToken ?? $this->id;
    }

    public function getClientId(): string
    {
        return $this->client_id;
    }

    public function getUserId(): ?string
    {
        return $this->user_id;
    }

    public function getScopes(): array
    {
        return json_decode($this->scopes ?? '[]', true) ?: [];
    }

    public function getExpiresAt(): \DateTimeImmutable
    {
        return (new \DateTimeImmutable())->setTimestamp($this->expires_at);
    }

    public function isRevoked(): bool
    {
        return (bool) $this->revoked;
    }

    // ---- Static finders ----

    /**
     * Check if a valid (non-revoked, non-expired) access token exists
     * for the given user+client covering all requested scopes.
     */
    public static function hasActiveToken(string $userId, string $clientId, array $scopes): bool
    {
        $tokens = static::find()
            ->where(['user_id' => $userId, 'client_id' => $clientId, 'revoked' => 0])
            ->andWhere(['>', 'expires_at', time()])
            ->all();

        foreach ($tokens as $token) {
            $tokenScopes = json_decode($token->scopes ?? '[]', true) ?: [];
            if (empty(array_diff($scopes, $tokenScopes))) {
                return true;
            }
        }

        return false;
    }

    /** Look up a token by its raw value (hashes it internally). */
    public static function findByRawToken(string $rawToken): ?static
    {
        $hash = TokenGenerator::hash($rawToken);
        $token = static::find()
            ->where(['id' => $hash, 'revoked' => 0])
            ->andWhere(['>', 'expires_at', time()])
            ->one();

        if ($token !== null) {
            $token->setRawToken($rawToken);
        }

        return $token;
    }

    /** Revoke a token by its raw value. */
    public static function revokeByRawToken(string $rawToken): void
    {
        static::updateAll(['revoked' => 1], ['id' => TokenGenerator::hash($rawToken)]);
    }
}
