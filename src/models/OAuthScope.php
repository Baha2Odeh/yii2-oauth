<?php

namespace baha2odeh\yii2oauth\models;

use baha2odeh\yii2oauth\contracts\entities\ScopeEntityInterface;
use yii\db\ActiveRecord;

/**
 * @property string $identifier
 * @property string|null $description
 * @property int $is_default
 */
class OAuthScope extends ActiveRecord implements ScopeEntityInterface
{
    public static function tableName(): string
    {
        return '{{%oauth_scopes}}';
    }

    public function rules(): array
    {
        return [
            [['identifier'], 'required'],
            [['identifier'], 'string', 'max' => 80],
            [['description'], 'string', 'max' => 500],
            [['is_default'], 'boolean'],
            [['description'], 'default', 'value' => null],
        ];
    }

    // ---- ScopeEntityInterface ----

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function isDefault(): bool
    {
        return (bool) $this->is_default;
    }

    // ---- Static finders ----

    public static function findByIdentifier(string $identifier): ?static
    {
        return static::find()->where(['identifier' => $identifier])->one();
    }

    /** @return static[] */
    public static function findDefaults(): array
    {
        return static::find()->where(['is_default' => 1])->all();
    }
}
