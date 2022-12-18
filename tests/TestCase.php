<?php

namespace sizeg\jwt\tests;

use yii\console\Application;

/**
 * Class TestCase
 * @author SiZE
 */
class TestCase extends \PHPUnit\Framework\TestCase
{

    /**
     * @inheritdoc
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->mockApplication();
    }

    /**
     * @inheritdoc
     */
    protected function tearDown(): void
    {
        $this->destroyApplication();
        parent::tearDown();
    }

    protected function mockApplication()
    {
        new Application([
            'id' => 'testapp',
            'basePath' => __DIR__,
            'vendorPath' => dirname(__DIR__) . '/vendor',
            'runtimePath' => __DIR__ . '/runtime',
        ]);
    }

    protected function destroyApplication()
    {
        \Yii::$app = null;
    }
}