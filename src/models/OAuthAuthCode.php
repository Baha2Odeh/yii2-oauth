<?php

namespace baha2odeh\yii2oauth\models;

use baha2odeh\yii2oauth\contracts\entities\AuthCodeEntityInterface;
use baha2odeh\yii2oauth\services\TokenGenerator;
use yii\db\ActiveRecord;

/**
 * @property string      $id                    SHA-256 hash of raw auth code
 * @property string      $client_id
 * @property string      $user_id
 * @property string      $redirect_uri
 * @property string|null $scopes                JSON array
 * @property string|null $code_challenge
 * @property string|null $code_challenge_method
 * @property int         $revoked
 * @property int         $expires_at
 * @property int         $created_at
 */
class OAuthAuthCode extends ActiveRecord implements AuthCodeEntityInterface
{
    /** Raw auth code — set after generation, never persisted. */
    private ?string $_rawCode = null;

    public static function tableName(): string
    {
        return '{{%oauth_auth_codes}}';
    }

    public function rules(): array
    {
        return [
            [['id', 'client_id', 'user_id', 'redirect_uri', 'expires_at', 'created_at'], 'required'],
            [['id', 'client_id'], 'string', 'max' => 80],
            [['user_id'], 'string', 'max' => 255],
            [['redirect_uri'], 'string', 'max' => 2000],
            [['scopes'], 'string'],
            [['code_challenge'], 'string', 'max' => 128],
            [['code_challenge_method'], 'string', 'max' => 6],
            [['revoked'], 'boolean'],
            [['expires_at', 'created_at'], 'integer'],
            [['scopes', 'code_challenge', 'code_challenge_method'], 'default', 'value' => null],
        ];
    }

    // ---- Raw code management ----

    public function setRawCode(string $raw): void
    {
        $this->_rawCode = $raw;
    }

    // ---- AuthCodeEntityInterface ----

    public function getIdentifier(): string
    {
        return $this->_rawCode ?? $this->id;
    }

    public function getClientId(): string
    {
        return $this->client_id;
    }

    public function getUserId(): string
    {
        return $this->user_id;
    }

    public function getRedirectUri(): string
    {
        return $this->redirect_uri;
    }

    public function getScopes(): array
    {
        return json_decode($this->scopes ?? '[]', true) ?: [];
    }

    public function getCodeChallenge(): ?string
    {
        return $this->code_challenge;
    }

    public function getCodeChallengeMethod(): ?string
    {
        return $this->code_challenge_method;
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

    public static function findByRawCode(string $rawCode): ?static
    {
        $hash = TokenGenerator::hash($rawCode);
        $code = static::find()
            ->where(['id' => $hash, 'revoked' => 0])
            ->andWhere(['>', 'expires_at', time()])
            ->one();

        if ($code !== null) {
            $code->setRawCode($rawCode);
        }

        return $code;
    }

    public static function revokeByRawCode(string $rawCode): void
    {
        static::updateAll(['revoked' => 1], ['id' => TokenGenerator::hash($rawCode)]);
    }
}
