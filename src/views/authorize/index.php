<?php
/**
 * Default OAuth2 consent/authorization view.
 *
 * Variables available:
 * @var \yii\web\View $this
 * @var \baha2odeh\yii2oauth\contracts\entities\ClientEntityInterface $client
 * @var array<string, string> $scopes  identifier => description
 * @var string|null $state
 * @var \baha2odeh\yii2oauth\actions\AuthorizeAction $action
 */

use yii\helpers\Html;

$this->title = 'Authorize Application';
?>
<div class="oauth-authorize">
    <h1><?= Html::encode($this->title) ?></h1>

    <p>
        <strong><?= Html::encode($client->getName()) ?></strong>
        is requesting access to your account.
    </p>

    <?php if (!empty($scopes)): ?>
        <h3>Requested permissions:</h3>
        <ul>
            <?php foreach ($scopes as $identifier => $description): ?>
                <li><?= Html::encode($description ?: $identifier) ?></li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>

    <?php $form = \yii\widgets\ActiveForm::begin([
        'action' => ['/' . \Yii::$app->controller->module->id . '/authorize'],
        'method' => 'post',
    ]); ?>

    <?= Html::hiddenInput('state', $state) ?>

    <div class="oauth-authorize-buttons">
        <?= Html::submitButton('Allow', ['name' => 'approved', 'value' => '1', 'class' => 'btn btn-success']) ?>
        <?= Html::submitButton('Deny', ['name' => 'approved', 'value' => '0', 'class' => 'btn btn-danger']) ?>
    </div>

    <?php \yii\widgets\ActiveForm::end(); ?>
</div>
