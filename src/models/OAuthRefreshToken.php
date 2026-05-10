<?php

namespace baha2odeh\yii2oauth\models;

use baha2odeh\yii2oauth\contracts\entities\RefreshTokenEntityInterface;
use baha2odeh\yii2oauth\services\TokenGenerator;
use yii\db\ActiveRecord;

/**
 * @property string $id               SHA-256 hash of raw refresh token
 * @property string $access_token_id  SHA-256 hash of the associated access token
 * @property int $revoked
 * @property int $expires_at
 * @property int $created_at
 */
class OAuthRefreshToken extends ActiveRecord implements RefreshTokenEntityInterface
{
    /** Raw refresh token — set after generation, never persisted. */
    private ?string $_rawToken = null;

    public static function tableName(): string
    {
        return '{{%oauth_refresh_tokens}}';
    }

    public function rules(): array
    {
        return [
            [['id', 'access_token_id', 'expires_at', 'created_at'], 'required'],
            [['id', 'access_token_id'], 'string', 'max' => 80],
            [['revoked'], 'boolean'],
            [['expires_at', 'created_at'], 'integer'],
        ];
    }

    // ---- Raw token management ----

    public function setRawToken(string $raw): void
    {
        $this->_rawToken = $raw;
    }

    // ---- RefreshTokenEntityInterface ----

    public function getIdentifier(): string
    {
        return $this->_rawToken ?? $this->id;
    }

    public function getAccessTokenId(): string
    {
        return $this->access_token_id;
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

    public static function revokeByRawToken(string $rawToken): void
    {
        static::updateAll(['revoked' => 1], ['id' => TokenGenerator::hash($rawToken)]);
    }

    /** Revoke by the associated access token hash (used when rotating tokens). */
    public static function revokeByAccessTokenId(string $accessTokenHash): void
    {
        static::updateAll(['revoked' => 1], ['access_token_id' => $accessTokenHash]);
    }
}
