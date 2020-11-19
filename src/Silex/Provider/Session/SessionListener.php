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
use Symfony\Component\HttpKernel\Event\FinishRequestEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\EventListener\SessionListener as DefaultSessionListener;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Sets the session in the request.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class SessionListener implements EventSubscriberInterface
{
    private $app;

    /**
     * @var DefaultSessionListener
     */
    private $listener;

    public function __construct(Container $app)
    {
        $this->listener = new DefaultSessionListener(new Psr11Container($app), $app['debug']);
        $this->app = $app;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 128],
            // low priority to come after regular response listeners, but higher than StreamedResponseListener
            KernelEvents::RESPONSE => ['onKernelResponse', -1000],
            KernelEvents::FINISH_REQUEST => ['onFinishRequest'],
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

    public function onFinishRequest(FinishRequestEvent $event)
    {
        $this->listener->onFinishRequest($event);
    }

    protected function getSession(): ?SessionInterface
    {
        return $this->app['session'] ?? null;
    }
}
