<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Silex\Tests\Provider;

use Exception;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Monolog\Formatter\JsonFormatter;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use RuntimeException;
use Silex\Application;
use Silex\Provider\MonologServiceProvider;
use Silex\Provider\SecurityServiceProvider;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * MonologProvider test cases.
 *
 * @author Igor Wiedler <igor@wiedler.ch>
 */
class MonologServiceProviderTest extends TestCase
{
    private $currErrorHandler;

    protected function setUp(): void
    {
        $this->currErrorHandler = set_error_handler('var_dump');
        restore_error_handler();
    }

    protected function tearDown(): void
    {
        set_error_handler($this->currErrorHandler);
    }

    public function testRequestLogging()
    {
        $app = $this->getApplication();

        $app->get(
            '/foo',
            function () use ($app) {
                return 'foo';
            }
        );

        self::assertFalse($app['monolog.handler']->hasInfoRecords());

        $request = Request::create('/foo');
        $app->handle($request);

        self::assertTrue($app['monolog.handler']->hasDebug('> GET /foo'));
        self::assertTrue($app['monolog.handler']->hasDebug('< 200'));

        $records = $app['monolog.handler']->getRecords();
        self::assertStringContainsString('Matched route "{route}".', $records[0]['message']);
        self::assertSame('GET_foo', $records[0]['context']['route']);
    }

    public function testManualLogging()
    {
        $app = $this->getApplication();

        $app->get('/log', function () use ($app) {
            $app['monolog']->addRecord(Logger::DEBUG, 'logging a message');
        });

        self::assertFalse($app['monolog.handler']->hasDebugRecords());

        $request = Request::create('/log');
        $app->handle($request);

        self::assertTrue($app['monolog.handler']->hasDebug('logging a message'));
    }

    public function testOverrideFormatter()
    {
        $app = new Application();

        $app->register(new MonologServiceProvider(), [
            'monolog.formatter' => new JsonFormatter(),
            'monolog.logfile' => 'php://memory',
        ]);

        self::assertInstanceOf('Monolog\Formatter\JsonFormatter', $app['monolog.handler']->getFormatter());
    }

    public function testErrorLogging()
    {
        $app = $this->getApplication();

        $app->error(
            function (Exception $e) {
                return 'error handled';
            }
        );

        /*
         * Simulate 404, logged to error level
         */
        self::assertFalse($app['monolog.handler']->hasErrorRecords());

        $request = Request::create('/error');
        $app->handle($request);

        $pattern = "#Symfony\\\\Component\\\\HttpKernel\\\\Exception\\\\NotFoundHttpException: No route found for \"GET /error\" \(uncaught exception\) at .* line \d+#";
        $this->assertMatchingRecord($pattern, Logger::ERROR, $app['monolog.handler']);

        /*
         * Simulate unhandled exception, logged to critical
         */
        $app->get('/error', function () {
            throw new RuntimeException('very bad error');
        });

        self::assertFalse($app['monolog.handler']->hasCriticalRecords());

        $request = Request::create('/error');
        $app->handle($request);

        $pattern = "#RuntimeException: very bad error \(uncaught exception\) at .* line \d+#";
        $this->assertMatchingRecord($pattern, Logger::CRITICAL, $app['monolog.handler']);
    }

    public function testRedirectLogging()
    {
        $app = $this->getApplication();

        $app->get('/foo', function () use ($app) {
            return new RedirectResponse('/bar', 302);
        });

        self::assertFalse($app['monolog.handler']->hasInfoRecords());

        $request = Request::create('/foo');
        $app->handle($request);

        self::assertTrue($app['monolog.handler']->hasDebug('< 302 /bar'));
    }

    public function testErrorLoggingGivesWayToSecurityExceptionHandling()
    {
        $app = $this->getApplication();
        $app['monolog.level'] = Logger::ERROR;

        $app->register(
            new SecurityServiceProvider(),
            [
                'security.firewalls' => [
                    'admin' => [
                        'pattern' => '^/admin',
                        'http' => true,
                        'users' => [],
                    ],
                ],
            ]
        );

        $app->get('/admin', function () {
            return 'SECURE!';
        });

        $request = Request::create('/admin');
        $app->run($request);

        self::assertEmpty($app['monolog.handler']->getRecords(), 'Expected no logging to occur');
    }

    public function testStringErrorLevel()
    {
        $app = $this->getApplication();
        $app['monolog.level'] = 'info';

        self::assertSame(Logger::INFO, $app['monolog.handler']->getLevel());
    }

    public function testNonExistentStringErrorLevel()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Level "foo" is not defined, use one of: 100, 200, 250, 300, 400, 500, 550, 600');
        $app = $this->getApplication();
        $app['monolog.level'] = 'foo';

        $app['monolog.handler']->getLevel();
    }

    public function testDisableListener()
    {
        $app = $this->getApplication();
        unset($app['monolog.listener']);

        $app->handle(Request::create('/404'));

        self::assertEmpty($app['monolog.handler']->getRecords(), 'Expected no logging to occur');
    }

    public function testExceptionFiltering()
    {
        $app = new Application();
        $app->get('/foo', function () use ($app) {
            throw new NotFoundHttpException();
        });

        $level = Logger::ERROR;
        $app->register(new MonologServiceProvider(), [
            'monolog.exception.logger_filter' => $app->protect(function () {
                return Logger::DEBUG;
            }),
            'monolog.handler' => function () use ($app) {
                return new TestHandler($app['monolog.level']);
            },
            'monolog.level' => $level,
            'monolog.logfile' => 'php://memory',
        ]);

        $request = Request::create('/foo');
        $app->handle($request);

        self::assertCount(0, $app['monolog.handler']->getRecords(), 'Expected no logging to occur');
    }

    protected function assertMatchingRecord($pattern, $level, TestHandler $handler)
    {
        $found = false;
        $records = $handler->getRecords();
        foreach ($records as $record) {
            if (preg_match($pattern, $record['message']) && $record['level'] == $level) {
                $found = true;
                continue;
            }
        }
        self::assertTrue($found, "Trying to find record matching $pattern with level $level");
    }

    protected function getApplication()
    {
        $app = new Application();

        $app->register(new MonologServiceProvider(), [
            'monolog.handler' => function () use ($app) {
                $level = MonologServiceProvider::translateLevel($app['monolog.level']);

                return new TestHandler($level);
            },
            'monolog.logfile' => 'php://memory',
        ]);

        return $app;
    }
}
