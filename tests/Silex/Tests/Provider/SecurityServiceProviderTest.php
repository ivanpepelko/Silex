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

use LogicException;
use Silex\Application;
use Silex\Provider\SecurityServiceProvider;
use Silex\Provider\SessionServiceProvider;
use Silex\Provider\ValidatorServiceProvider;
use Silex\WebTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\HttpKernelBrowser as Client;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

use function call_user_func;
use function is_object;

/**
 * SecurityServiceProvider.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class SecurityServiceProviderTest extends WebTestCase
{
    public function testWrongAuthenticationType()
    {
        $this->expectException(LogicException::class);
        $app = new Application();
        $app->register(new SecurityServiceProvider(), [
            'security.firewalls' => [
                'wrong' => [
                    'foobar' => true,
                    'users' => [],
                ],
            ],
        ]);
        $app->get('/', function () {});
        $app->handle(Request::create('/'));
    }

    public function testFormAuthentication()
    {
        $app = $this->createApplication('form');

        $client = new Client($app);

        $client->request('get', '/');
        self::assertEquals('ANONYMOUS', $client->getResponse()->getContent());

        $client->request('post', '/login_check', ['_username' => 'fabien', '_password' => 'bar']);
        self::assertStringContainsString('Bad credentials', $app['security.last_error']($client->getRequest()));
        // hack to re-close the session as the previous assertions re-opens it
        $client->getRequest()->getSession()->save();

        $client->request('post', '/login_check', ['_username' => 'fabien', '_password' => 'foo']);
        self::assertEquals('', $app['security.last_error']($client->getRequest()));
        $client->getRequest()->getSession()->save();
        self::assertEquals(302, $client->getResponse()->getStatusCode());
        self::assertEquals('http://localhost/', $client->getResponse()->getTargetUrl());

        $client->request('get', '/');
        self::assertEquals('fabienAUTHENTICATED', $client->getResponse()->getContent());
        $client->request('get', '/admin');
        self::assertEquals(403, $client->getResponse()->getStatusCode());

        $client->request('get', '/logout');
        self::assertEquals(302, $client->getResponse()->getStatusCode());
        self::assertEquals('http://localhost/', $client->getResponse()->getTargetUrl());

        $client->request('get', '/');
        self::assertEquals('ANONYMOUS', $client->getResponse()->getContent());

        $client->request('get', '/admin');
        self::assertEquals(302, $client->getResponse()->getStatusCode());
        self::assertEquals('http://localhost/login', $client->getResponse()->getTargetUrl());

        $client->request('post', '/login_check', ['_username' => 'admin', '_password' => 'foo']);
        self::assertEquals('', $app['security.last_error']($client->getRequest()));
        $client->getRequest()->getSession()->save();
        self::assertEquals(302, $client->getResponse()->getStatusCode());
        self::assertEquals('http://localhost/admin', $client->getResponse()->getTargetUrl());

        $client->request('get', '/');
        self::assertEquals('adminAUTHENTICATEDADMIN', $client->getResponse()->getContent());
        $client->request('get', '/admin');
        self::assertEquals('admin', $client->getResponse()->getContent());
    }

    public function testHttpAuthentication()
    {
        $app = $this->createApplication('http');

        $client = new Client($app);

        $client->request('get', '/');
        self::assertEquals(401, $client->getResponse()->getStatusCode());
        self::assertEquals('Basic realm="Secured"', $client->getResponse()->headers->get('www-authenticate'));

        $client->request('get', '/', [], [], ['PHP_AUTH_USER' => 'dennis', 'PHP_AUTH_PW' => 'foo']);
        self::assertEquals('dennisAUTHENTICATED', $client->getResponse()->getContent());
        $client->request('get', '/admin');
        self::assertEquals(403, $client->getResponse()->getStatusCode());

        $client->restart();

        $client->request('get', '/');
        self::assertEquals(401, $client->getResponse()->getStatusCode());
        self::assertEquals('Basic realm="Secured"', $client->getResponse()->headers->get('www-authenticate'));

        $client->request('get', '/', [], [], ['PHP_AUTH_USER' => 'admin', 'PHP_AUTH_PW' => 'foo']);
        self::assertEquals('adminAUTHENTICATEDADMIN', $client->getResponse()->getContent());
        $client->request('get', '/admin');
        self::assertEquals('admin', $client->getResponse()->getContent());
    }

    public function testGuardAuthentication()
    {
        $app = $this->createApplication('guard');

        $client = new Client($app);

        $client->request('get', '/');
        self::assertEquals(401, $client->getResponse()->getStatusCode(), 'The entry point is configured');
        self::assertEquals('{"message":"Authentication Required"}', $client->getResponse()->getContent());

        $client->request('get', '/', [], [], ['HTTP_X_AUTH_TOKEN' => 'lili:not the secret']);
        self::assertEquals(403, $client->getResponse()->getStatusCode(), 'User not found');
        self::assertEquals('{"message":"Invalid credentials."}', $client->getResponse()->getContent());

        $client->request('get', '/', [], [], ['HTTP_X_AUTH_TOKEN' => 'victoria:not the secret']);
        self::assertEquals(403, $client->getResponse()->getStatusCode(), 'Invalid credentials');
        self::assertEquals('{"message":"Invalid credentials."}', $client->getResponse()->getContent());

        $client->request('get', '/', [], [], ['HTTP_X_AUTH_TOKEN' => 'victoria:victoriasecret']);
        self::assertEquals('victoria', $client->getResponse()->getContent());
    }

    public function testUserPasswordValidatorIsRegistered()
    {
        $app = new Application();

        $app->register(new SecurityServiceProvider(), [
            'security.firewalls' => [
                'admin' => [
                    'pattern' => '^/admin',
                    'http' => true,
                    'users' => [
                        'admin' => ['ROLE_ADMIN', '513aeb0121909'],
                    ],
                ],
            ],
        ]
        );
        $app->register(new ValidatorServiceProvider());

        $app->boot();

        self::assertInstanceOf(
            'Symfony\Component\Security\Core\Validator\Constraints\UserPasswordValidator',
            $app['security.validator.user_password_validator']
        );
    }

    public function testExposedExceptions()
    {
        $app = $this->createApplication('form');
        $app['security.hide_user_not_found'] = false;

        $client = new Client($app);

        $client->request('get', '/');
        self::assertEquals('ANONYMOUS', $client->getResponse()->getContent());

        $client->request('post', '/login_check', ['_username' => 'fabien', '_password' => 'bar']);
        self::assertEquals('The presented password is invalid.', $app['security.last_error']($client->getRequest()));
        $client->getRequest()->getSession()->save();

        $client->request('post', '/login_check', ['_username' => 'unknown', '_password' => 'bar']);
        self::assertEquals('Username "unknown" does not exist.', $app['security.last_error']($client->getRequest()));
        $client->getRequest()->getSession()->save();

        $client->request('post', '/login_check', ['_username' => 'unknown', '_password' => 'bar']);
        $app['request_stack']->push($client->getRequest());
        $authenticationException = $app['security.authentication_utils']->getLastAuthenticationError();
        self::assertInstanceOf(AuthenticationException::class, $authenticationException);
        self::assertEquals('Username "unknown" does not exist.', $authenticationException->getMessage());
        $client->getRequest()->getSession()->save();
    }

    public function testFakeRoutesAreSerializable()
    {
        $app = new Application();

        $app->register(new SecurityServiceProvider(), [
            'security.firewalls' => [
                'admin' => [
                    'logout' => true,
                ],
            ],
        ]);

        $app->boot();
        $app->flush();

        self::assertCount(1, unserialize(serialize($app['routes'])));
    }

    public function testFirewallWithMethod()
    {
        $app = new Application();
        $app->register(new SecurityServiceProvider(), [
            'security.firewalls' => [
                'default' => [
                    'pattern' => '/',
                    'http' => true,
                    'methods' => ['POST'],
                ],
            ],
        ]);
        $app->match('/', function () { return 'foo'; })
            ->method('POST|GET');

        $request = Request::create('/', 'GET');
        $response = $app->handle($request);
        self::assertEquals(200, $response->getStatusCode());

        $request = Request::create('/', 'POST');
        $response = $app->handle($request);
        self::assertEquals(401, $response->getStatusCode());
    }

    public function testFirewallWithHost()
    {
        $app = new Application();
        $app->register(new SecurityServiceProvider(), [
            'security.firewalls' => [
                'default' => [
                    'pattern' => '/',
                    'http' => true,
                    'hosts' => 'localhost2',
                ],
            ],
        ]);
        $app->get('/', function () { return 'foo'; })
            ->host('localhost2');

        $app->get('/', function () { return 'foo'; })
            ->host('localhost1');

        $request = Request::create('http://localhost2/');
        $response = $app->handle($request);
        self::assertEquals(401, $response->getStatusCode());

        $request = Request::create('http://localhost1/');
        $response = $app->handle($request);
        self::assertEquals(200, $response->getStatusCode());
    }

    public function testUser()
    {
        $app = new Application();
        $app->register(
            new SecurityServiceProvider(),
            [
                'security.firewalls' => [
                    'default' => [
                        'http' => true,
                        'users' => [
                            'fabien' => ['ROLE_ADMIN', '$2y$15$lzUNsTegNXvZW3qtfucV0erYBcEqWVeyOmjolB7R1uodsAVJ95vvu'],
                        ],
                    ],
                ],
            ]
        );
        $app->get('/', function () { return 'foo'; });

        $request = Request::create('/');
        $app->handle($request);
        self::assertNull($app['user']);

        $request->headers->set('PHP_AUTH_USER', 'fabien');
        $request->headers->set('PHP_AUTH_PW', 'foo');
        $app->handle($request);
        self::assertInstanceOf('Symfony\Component\Security\Core\User\UserInterface', $app['user']);
        self::assertEquals('fabien', $app['user']->getUsername());
    }

    public function testUserAsServiceString()
    {
        $users = [
            'fabien' => ['ROLE_ADMIN', '$2y$15$lzUNsTegNXvZW3qtfucV0erYBcEqWVeyOmjolB7R1uodsAVJ95vvu'],
        ];

        $app = new Application();
        $app->register(
            new SecurityServiceProvider(),
            [
                'security.firewalls' => [
                    'default' => [
                        'http' => true,
                        'users' => 'my_user_provider',
                    ],
                ],
            ]
        );
        $app['my_user_provider'] = $app['security.user_provider.inmemory._proto']($users);
        $app->get('/', function () { return 'foo'; });

        $request = Request::create('/');
        $app->handle($request);
        self::assertNull($app['user']);
        self::assertSame($app['my_user_provider'], $app['security.user_provider.default']);

        $request->headers->set('PHP_AUTH_USER', 'fabien');
        $request->headers->set('PHP_AUTH_PW', 'foo');
        $app->handle($request);
        self::assertInstanceOf('Symfony\Component\Security\Core\User\UserInterface', $app['user']);
        self::assertEquals('fabien', $app['user']->getUsername());
    }

    public function testUserWithNoToken()
    {
        $app = new Application();
        $app->register(new SecurityServiceProvider(), [
            'security.firewalls' => [
                'default' => [
                    'http' => true,
                ],
            ],
        ]);

        $request = Request::create('/');

        $app->get('/', function () { return 'foo'; });
        $app->handle($request);
        self::assertNull($app['user']);
    }

    public function testUserWithInvalidUser()
    {
        $app = new Application();
        $app->register(new SecurityServiceProvider(), [
            'security.firewalls' => [
                'default' => [
                    'http' => true,
                ],
            ],
        ]);

        $request = Request::create('/');
        $app->boot();
        $app['security.token_storage']->setToken(new UsernamePasswordToken('foo', 'foo', 'foo'));

        $app->get('/', function () { return 'foo'; });
        $app->handle($request);
        self::assertNull($app['user']);
    }

    public function testAccessRulePathArray()
    {
        $app = new Application();
        $app->register(new SecurityServiceProvider(), [
            'security.firewalls' => [
                'default' => [
                    'http' => true,
                ],
            ],
            'security.access_rules' => [
                [
                    [
                        'path' => '^/admin',
                    ],
                    'ROLE_ADMIN',
                ],
            ],
        ]
        );

        $request = Request::create('/admin');
        $app->boot();
        $accessMap = $app['security.access_map'];
        self::assertEquals(
            $accessMap->getPatterns($request),
            [
                ['ROLE_ADMIN'],
                '',
            ]
        );
    }

    public function createApplication($authenticationMethod = 'form')
    {
        $app = new Application();
        $app->register(new SessionServiceProvider());

        $app = call_user_func([$this, 'add'.ucfirst($authenticationMethod).'Authentication'], $app);

        $app['session.test'] = true;

        return $app;
    }

    private function addFormAuthentication($app)
    {
        $app->register(new SecurityServiceProvider(), [
            'security.firewalls' => [
                'login' => [
                    'pattern' => '^/login$',
                ],
                'default' => [
                    'pattern' => '^.*$',
                    'anonymous' => true,
                    'form' => [
                        'require_previous_session' => false,
                    ],
                    'logout' => true,
                    'users' => [
                        // password is foo
                        'fabien' => ['ROLE_USER', '$2y$15$lzUNsTegNXvZW3qtfucV0erYBcEqWVeyOmjolB7R1uodsAVJ95vvu'],
                        'admin' => ['ROLE_ADMIN', '$2y$15$lzUNsTegNXvZW3qtfucV0erYBcEqWVeyOmjolB7R1uodsAVJ95vvu'],
                    ],
                ],
            ],
            'security.access_rules' => [
                ['^/admin', 'ROLE_ADMIN'],
            ],
            'security.role_hierarchy' => [
                'ROLE_ADMIN' => ['ROLE_USER'],
            ],
        ]);

        $app->get('/login', function (Request $request) use ($app) {
            $app['session']->start();

            return $app['security.last_error']($request);
        });

        $app->get('/', function () use ($app) {
            $user = $app['security.token_storage']->getToken()->getUser();

            $content = is_object($user) ? $user->getUsername() : 'ANONYMOUS';

            if ($app['security.authorization_checker']->isGranted('IS_AUTHENTICATED_FULLY')) {
                $content .= 'AUTHENTICATED';
            }

            if ($app['security.authorization_checker']->isGranted('ROLE_ADMIN')) {
                $content .= 'ADMIN';
            }

            return $content;
        });

        $app->get('/admin', function () use ($app) {
            return 'admin';
        });

        return $app;
    }

    private function addHttpAuthentication($app)
    {
        $app->register(new SecurityServiceProvider(), [
            'security.firewalls' => [
                'http-auth' => [
                    'pattern' => '^.*$',
                    'http' => true,
                    'users' => [
                        // password is foo
                        'dennis' => ['ROLE_USER', '$2y$15$lzUNsTegNXvZW3qtfucV0erYBcEqWVeyOmjolB7R1uodsAVJ95vvu'],
                        'admin' => ['ROLE_ADMIN', '$2y$15$lzUNsTegNXvZW3qtfucV0erYBcEqWVeyOmjolB7R1uodsAVJ95vvu'],
                    ],
                ],
            ],
            'security.access_rules' => [
                ['^/admin', 'ROLE_ADMIN'],
            ],
            'security.role_hierarchy' => [
                'ROLE_ADMIN' => ['ROLE_USER'],
            ],
        ]);

        $app->get('/', function () use ($app) {
            $user = $app['security.token_storage']->getToken()->getUser();
            $content = is_object($user) ? $user->getUsername() : 'ANONYMOUS';

            if ($app['security.authorization_checker']->isGranted('IS_AUTHENTICATED_FULLY')) {
                $content .= 'AUTHENTICATED';
            }

            if ($app['security.authorization_checker']->isGranted('ROLE_ADMIN')) {
                $content .= 'ADMIN';
            }

            return $content;
        });

        $app->get('/admin', function () use ($app) {
            return 'admin';
        });

        return $app;
    }

    private function addGuardAuthentication($app)
    {
        $app['app.authenticator.token'] = function ($app) {
            return new SecurityServiceProviderTest\TokenAuthenticator($app);
        };

        $app->register(new SecurityServiceProvider(), [
            'security.firewalls' => [
                'guard' => [
                    'pattern' => '^.*$',
                    'form' => true,
                    'guard' => [
                        'authenticators' => [
                            'app.authenticator.token',
                        ],
                    ],
                    'users' => [
                        'victoria' => ['ROLE_USER', 'victoriasecret'],
                    ],
                ],
            ],
        ]);

        $app->get('/', function () use ($app) {
            $user = $app['security.token_storage']->getToken()->getUser();

            $content = is_object($user) ? $user->getUsername() : 'ANONYMOUS';

            return $content;
        })->bind('homepage');

        return $app;
    }
}
