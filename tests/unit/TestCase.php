<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit;

use PHPUnit\Framework\TestCase as BaseTestCase;

/**
 * Base class for all tests that touch the database.
 * Each test runs inside a transaction that is rolled back in tearDown,
 * keeping tests fully isolated without re-running the migration.
 */
abstract class TestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        \Yii::$app->db->beginTransaction();
    }

    protected function tearDown(): void
    {
        $transaction = \Yii::$app->db->transaction;
        if ($transaction !== null && $transaction->getIsActive()) {
            $transaction->rollBack();
        }
        parent::tearDown();
    }

    /** Helper: hash a password the same way the OAuthClient model expects. */
    protected function hashPassword(string $raw): string
    {
        return \Yii::$app->security->generatePasswordHash($raw);
    }
}
