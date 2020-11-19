<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Silex\Provider\Session;

use Pimple\Container;
use Pimple\Psr11\Container as Psr11Container;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\EventListener\TestSessionListener as DefaultTestSessionListener;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Simulates sessions for testing purpose.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
final class TestSessionListener implements EventSubscriberInterface
{
    private $app;

    /**
     * @var DefaultTestSessionListener
     */
    private $listener;

    public function __construct(Container $app)
    {
        $this->app = $app;
        $this->listener = new DefaultTestSessionListener(new Psr11Container($app));
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 192],
            KernelEvents::RESPONSE => ['onKernelResponse', -128],
        ];
    }

    public function onKernelRequest(RequestEvent $event)
    {
        $this->listener->onKernelRequest($event);
    }

    public function onKernelResponse(ResponseEvent $event)
    {
        $this->listener->onKernelResponse($event);
    }

    protected function getSession(): ?SessionInterface
    {
        return $this->app['session'] ?? null;
    }
}
