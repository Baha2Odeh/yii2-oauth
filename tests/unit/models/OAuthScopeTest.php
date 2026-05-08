<?php

declare(strict_types=1);

namespace baha2odeh\yii2oauth\tests\unit\models;

use baha2odeh\yii2oauth\models\OAuthScope;
use baha2odeh\yii2oauth\tests\unit\TestCase;

class OAuthScopeTest extends TestCase
{
    private function makeScope(string $identifier, string $description = '', int $isDefault = 0): OAuthScope
    {
        $scope = new OAuthScope();
        $scope->identifier = $identifier;
        $scope->description = $description ?: null;
        $scope->is_default = $isDefault;
        $scope->save(false);

        return $scope;
    }

    public function testGetIdentifier(): void
    {
        $scope = $this->makeScope('openid');
        $this->assertSame('openid', $scope->getIdentifier());
    }

    public function testGetDescription(): void
    {
        $scope = $this->makeScope('profile', 'User profile information');
        $this->assertSame('User profile information', $scope->getDescription());
    }

    public function testGetDescriptionNullWhenEmpty(): void
    {
        $scope = $this->makeScope('email');
        $this->assertNull($scope->getDescription());
    }

    public function testIsDefaultTrue(): void
    {
        $scope = $this->makeScope('openid', 'OpenID', 1);
        $this->assertTrue($scope->isDefault());
    }

    public function testIsDefaultFalse(): void
    {
        $scope = $this->makeScope('admin', 'Admin access', 0);
        $this->assertFalse($scope->isDefault());
    }

    public function testFindByIdentifier(): void
    {
        $this->makeScope('read', 'Read access');

        $found = OAuthScope::findByIdentifier('read');

        $this->assertNotNull($found);
        $this->assertSame('read', $found->getIdentifier());
    }

    public function testFindByIdentifierReturnsNullForMissing(): void
    {
        $this->assertNull(OAuthScope::findByIdentifier('nonexistent_scope'));
    }

    public function testFindDefaults(): void
    {
        $this->makeScope('openid', 'OpenID', 1);
        $this->makeScope('profile', 'Profile', 1);
        $this->makeScope('admin', 'Admin', 0);

        $defaults = OAuthScope::findDefaults();

        $this->assertCount(2, $defaults);
        $identifiers = array_map(fn($s) => $s->getIdentifier(), $defaults);
        $this->assertContains('openid', $identifiers);
        $this->assertContains('profile', $identifiers);
        $this->assertNotContains('admin', $identifiers);
    }

    public function testFindDefaultsReturnsEmptyWhenNoneSet(): void
    {
        $this->makeScope('write', 'Write access', 0);

        $this->assertSame([], OAuthScope::findDefaults());
    }
}
