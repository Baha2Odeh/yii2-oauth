<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\support;

use baha2odeh\yii2oauth\contracts\entities\UserEntityInterface;

/**
 * In-memory user stub for testing the password grant.
 * Does NOT extend ActiveRecord — no DB required.
 */
class TestUserModel implements UserEntityInterface
{
    /** Simulated user store: username => ['password' => raw, 'id' => string] */
    private static array $store = [];

    private string $id;
    private array $claims;

    public function __construct(string $id, array $claims = [])
    {
        $this->id = $id;
        $this->claims = $claims;
    }

    public function getIdentifier(): string
    {
        return $this->id;
    }

    public function getClaims(array $scopes = []): array
    {
        if (empty($scopes)) {
            return $this->claims;
        }

        $allowed = [];
        if (in_array('profile', $scopes, true)) {
            foreach (['name', 'given_name', 'family_name', 'picture'] as $k) {
                if (isset($this->claims[$k])) {
                    $allowed[$k] = $this->claims[$k];
                }
            }
        }
        if (in_array('email', $scopes, true) && isset($this->claims['email'])) {
            $allowed['email'] = $this->claims['email'];
        }

        return $allowed;
    }

    // ---- Static API expected by PasswordGrant ----

    public static function seed(string $username, string $password, string $id): void
    {
        self::$store[$username] = ['password' => $password, 'id' => $id];
    }

    public static function reset(): void
    {
        self::$store = [];
    }

    public static function findByCredentials(string $username, string $password): ?static
    {
        if (!isset(self::$store[$username])) {
            return null;
        }
        if (self::$store[$username]['password'] !== $password) {
            return null;
        }
        return new static(self::$store[$username]['id'], ['email' => "{$username}@example.com"]);
    }

    // ---- findIdentity for UserinfoAction ----

    public static function findIdentity(int|string $id): ?static
    {
        foreach (self::$store as $username => $data) {
            if ((string) $data['id'] === (string) $id) {
                return new static($data['id'], ['email' => "{$username}@example.com"]);
            }
        }
        return null;
    }
}
