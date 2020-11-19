<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Silex\Tests\EventListener;

use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;
use RuntimeException;
use Silex\EventListener\LogListener;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * LogListener.
 *
 * @author Jérôme Tamarelle <jerome@tamarelle.net>
 */
class LogListenerTest extends TestCase
{
    public function testRequestListener()
    {
        $logger = $this->getMockBuilder(LoggerInterface::class)->getMock();
        $logger
            ->expects(self::once())
            ->method('log')
            ->with(LogLevel::DEBUG, '> GET /foo');

        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber(new LogListener($logger));

        /** @var HttpKernelInterface $kernel */
        $kernel = $this->getMockBuilder(HttpKernelInterface::class)->getMock();

        $dispatcher->dispatch(new RequestEvent($kernel, Request::create('/subrequest'), HttpKernelInterface::SUB_REQUEST), KernelEvents::REQUEST);

        $dispatcher->dispatch(new RequestEvent($kernel, Request::create('/foo'), HttpKernelInterface::MASTER_REQUEST), KernelEvents::REQUEST);
    }

    public function testResponseListener()
    {
        $logger = $this->getMockBuilder(LoggerInterface::class)->getMock();
        $logger
            ->expects(self::once())
            ->method('log')
            ->with(LogLevel::DEBUG, '< 301');

        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber(new LogListener($logger));

        $kernel = $this->getMockBuilder(HttpKernelInterface::class)->getMock();

        $dispatcher->dispatch(
            new ResponseEvent($kernel, Request::create('/foo'), HttpKernelInterface::SUB_REQUEST, new Response('subrequest', 200)),
            KernelEvents::RESPONSE
        );

        $dispatcher->dispatch(
            new ResponseEvent($kernel, Request::create('/foo'), HttpKernelInterface::MASTER_REQUEST, new Response('bar', 301)),
            KernelEvents::RESPONSE
        );
    }

    public function testExceptionListener()
    {
        $logger = $this->getMockBuilder(LoggerInterface::class)->getMock();
        $logger
            ->expects(self::at(0))
            ->method('log')
            ->with(LogLevel::CRITICAL, 'RuntimeException: Fatal error (uncaught exception) at ' . __FILE__ . ' line ' . (__LINE__ + 14));
        $logger
            ->expects(self::at(1))
            ->method('log')
            ->with(
                LogLevel::ERROR,
                'Symfony\Component\HttpKernel\Exception\HttpException: Http error (uncaught exception) at ' . __FILE__ . ' line ' . (__LINE__ + 9)
            );

        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber(new LogListener($logger));

        $kernel = $this->getMockBuilder(HttpKernelInterface::class)->getMock();

        $dispatcher->dispatch(
            new ExceptionEvent($kernel, Request::create('/foo'), HttpKernelInterface::SUB_REQUEST, new RuntimeException('Fatal error')),
            KernelEvents::EXCEPTION
        );
        $dispatcher->dispatch(
            new ExceptionEvent($kernel, Request::create('/foo'), HttpKernelInterface::SUB_REQUEST, new HttpException(400, 'Http error')),
            KernelEvents::EXCEPTION
        );
    }
}
