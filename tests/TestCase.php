<?php

namespace sizeg\jwt\tests;

use yii\console\Application;

/**
 * Class TestCase
 * @author SiZE
 */
class TestCase extends \PHPUnit_Framework_TestCase
{

    /**
     * @inheritdoc
     */
    protected function setUp()
    {
        parent::setUp();
        $this->mockApplication();
    }

    /**
     * @inheritdoc
     */
    protected function tearDown()
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