<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Silex\Tests\Application;

use PHPUnit\Framework\TestCase;
use Silex\Provider\TwigServiceProvider;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Twig\Environment;

/**
 * @author Fabien Potencier <fabien@symfony.com>
 */
class TwigTraitTest extends TestCase
{
    public function testRender()
    {
        $app = $this->createApplication();

        $app['twig'] = $mailer = $this->getMockBuilder(Environment::class)->disableOriginalConstructor()->getMock();
        $mailer->expects(self::once())->method('render')->willReturn('foo');

        $response = $app->render('view');
        self::assertEquals(Response::class, get_class($response));
        self::assertEquals('foo', $response->getContent());
    }

    public function testRenderKeepResponse()
    {
        $app = $this->createApplication();

        $app['twig'] = $mailer = $this->getMockBuilder(Environment::class)->disableOriginalConstructor()->getMock();
        $mailer->expects(self::once())->method('render')->willReturn('foo');

        $response = $app->render('view', [], new Response('', 404));
        self::assertEquals(404, $response->getStatusCode());
    }

    public function testRenderForStream()
    {
        $app = $this->createApplication();

        $app['twig'] = $mailer = $this->getMockBuilder(Environment::class)->disableOriginalConstructor()->getMock();
        $mailer->expects(self::once())->method('display')->willReturnCallback(function () { echo 'foo'; });

        $response = $app->render('view', [], new StreamedResponse());
        self::assertEquals(StreamedResponse::class, get_class($response));

        ob_start();
        $response->send();
        self::assertEquals('foo', ob_get_clean());
    }

    public function testRenderView()
    {
        $app = $this->createApplication();

        $app['twig'] = $mailer = $this->getMockBuilder(Environment::class)->disableOriginalConstructor()->getMock();
        $mailer->expects(self::once())->method('render');

        $app->renderView('view');
    }

    public function createApplication()
    {
        $app = new TwigApplication();
        $app->register(new TwigServiceProvider());

        return $app;
    }
}
