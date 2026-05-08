<?php

use yii\db\Migration;

class m000000_000000_create_oauth_tables extends Migration
{
    public function safeUp(): void
    {
        $this->createTable('{{%oauth_clients}}', [
            'id'              => $this->string(80)->notNull()->append('PRIMARY KEY'),
            'name'            => $this->string(255)->notNull(),
            'secret'          => $this->string(255)->null()->defaultValue(null),
            'redirect_uris'   => $this->text()->notNull(),
            'grant_types'     => $this->string(500)->notNull(),
            'scopes'          => $this->string(500)->null()->defaultValue(null),
            'is_confidential' => $this->tinyInteger(1)->notNull()->defaultValue(1),
            'is_active'       => $this->tinyInteger(1)->notNull()->defaultValue(1),
            'require_pkce'    => $this->tinyInteger(1)->notNull()->defaultValue(0),
            'user_id'         => $this->integer()->null()->defaultValue(null),
            'created_at'      => $this->integer()->notNull(),
            'updated_at'      => $this->integer()->notNull(),
        ]);

        $this->createTable('{{%oauth_scopes}}', [
            'identifier'  => $this->string(80)->notNull()->append('PRIMARY KEY'),
            'description' => $this->string(500)->null()->defaultValue(null),
            'is_default'  => $this->tinyInteger(1)->notNull()->defaultValue(0),
        ]);

        $this->createTable('{{%oauth_access_tokens}}', [
            'id'         => $this->string(80)->notNull()->append('PRIMARY KEY'),
            'client_id'  => $this->string(80)->notNull(),
            'user_id'    => $this->string(255)->null()->defaultValue(null),
            'scopes'     => $this->text()->null()->defaultValue(null),
            'revoked'    => $this->tinyInteger(1)->notNull()->defaultValue(0),
            'expires_at' => $this->integer()->notNull(),
            'created_at' => $this->integer()->notNull(),
        ]);
        $this->createIndex('idx_at_client',  '{{%oauth_access_tokens}}', 'client_id');
        $this->createIndex('idx_at_user',    '{{%oauth_access_tokens}}', 'user_id');
        $this->createIndex('idx_at_expires', '{{%oauth_access_tokens}}', 'expires_at');

        $this->createTable('{{%oauth_refresh_tokens}}', [
            'id'              => $this->string(80)->notNull()->append('PRIMARY KEY'),
            'access_token_id' => $this->string(80)->notNull(),
            'revoked'         => $this->tinyInteger(1)->notNull()->defaultValue(0),
            'expires_at'      => $this->integer()->notNull(),
            'created_at'      => $this->integer()->notNull(),
        ]);
        $this->createIndex('idx_rt_at', '{{%oauth_refresh_tokens}}', 'access_token_id');

        $this->createTable('{{%oauth_auth_codes}}', [
            'id'                    => $this->string(80)->notNull()->append('PRIMARY KEY'),
            'client_id'             => $this->string(80)->notNull(),
            'user_id'               => $this->string(255)->notNull(),
            'redirect_uri'          => $this->string(2000)->notNull(),
            'scopes'                => $this->text()->null()->defaultValue(null),
            'code_challenge'        => $this->string(128)->null()->defaultValue(null),
            'code_challenge_method' => $this->string(6)->null()->defaultValue(null),
            'revoked'               => $this->tinyInteger(1)->notNull()->defaultValue(0),
            'expires_at'            => $this->integer()->notNull(),
            'created_at'            => $this->integer()->notNull(),
        ]);
        $this->createIndex('idx_ac_client', '{{%oauth_auth_codes}}', 'client_id');
    }

    public function safeDown(): void
    {
        $this->dropTable('{{%oauth_refresh_tokens}}');
        $this->dropTable('{{%oauth_access_tokens}}');
        $this->dropTable('{{%oauth_auth_codes}}');
        $this->dropTable('{{%oauth_scopes}}');
        $this->dropTable('{{%oauth_clients}}');
    }
}
