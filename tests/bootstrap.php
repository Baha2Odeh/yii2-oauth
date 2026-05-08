<?php

declare(strict_types=1);

defined('YII_DEBUG') or define('YII_DEBUG', true);
defined('YII_ENV') or define('YII_ENV', 'test');

require dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__) . '/vendor/yiisoft/yii2/Yii.php';
require dirname(__DIR__) . '/migrations/m000000_000000_create_oauth_tables.php';

// Minimal Yii2 console application backed by an in-memory SQLite database.
new \yii\console\Application([
    'id'       => 'yii2-oauth-tests',
    'basePath' => dirname(__DIR__),
    'aliases'  => [
        '@baha2odeh/yii2oauth' => dirname(__DIR__) . '/src',
    ],
    'components' => [
        'db' => [
            'class'   => \yii\db\Connection::class,
            'dsn'     => 'sqlite::memory:',
            'charset' => 'utf8',
        ],
        'security' => \yii\base\Security::class,
    ],
]);

// Run the extension migration once for the entire test run.
$migration = new \m000000_000000_create_oauth_tables();
$migration->safeUp();
