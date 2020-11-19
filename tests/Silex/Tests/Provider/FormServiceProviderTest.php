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

use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use Silex\Application;
use Silex\Provider\FormServiceProvider;
use Silex\Provider\CsrfServiceProvider;
use Silex\Provider\SessionServiceProvider;
use Silex\Provider\TranslationServiceProvider;
use Silex\Provider\ValidatorServiceProvider;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\AbstractTypeExtension;
use Symfony\Component\Form\Exception\InvalidArgumentException;
use Symfony\Component\Form\FormTypeGuesserChain;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Translation\Exception\NotFoundResourceException;
use Symfony\Component\Form\Extension\Core\Type\FileType;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Form\FormFactory;
use Symfony\Component\Form\Form;
use Symfony\Component\Form\FormRegistry;

class FormServiceProviderTest extends TestCase
{
    public function testFormFactoryServiceIsFormFactory()
    {
        $app = new Application();
        $app->register(new FormServiceProvider());
        self::assertInstanceOf(FormFactory::class, $app['form.factory']);
    }

    public function testFormRegistryServiceIsFormRegistry()
    {
        $app = new Application();
        $app->register(new FormServiceProvider());
        self::assertInstanceOf(FormRegistry::class, $app['form.registry']);
    }

    public function testFormServiceProviderWillLoadTypes()
    {
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app->extend(
            'form.types',
            function ($extensions) {
                $extensions[] = new DummyFormType();

                return $extensions;
            }
        );

        $form = $app['form.factory']->createBuilder(FormType::class, [])
            ->add('dummy', DummyFormType::class)
            ->getForm();

        self::assertInstanceOf(Form::class, $form);
    }

    public function testFormServiceProviderWillLoadTypesServices()
    {
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app['dummy'] = function () {
            return new DummyFormType();
        };
        $app->extend('form.types', function ($extensions) {
            $extensions[] = 'dummy';

            return $extensions;
        });

        $form = $app['form.factory']
            ->createBuilder(FormType::class, [])
            ->add('dummy', 'dummy')
            ->getForm();

        self::assertInstanceOf(Form::class, $form);
    }

    public function testNonExistentTypeService()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid form type. The silex service \"dummy\" does not exist.");
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app->extend(
            'form.types',
            function ($extensions) {
                $extensions[] = 'dummy';

                return $extensions;
            }
        );

        $app['form.factory']
            ->createBuilder(FormType::class, [])
            ->add('dummy', 'dummy')
            ->getForm();
    }

    public function testFormServiceProviderWillLoadTypeExtensions()
    {
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app->extend(
            'form.type.extensions',
            function ($extensions) {
                $extensions[] = new DummyFormTypeExtension();

                return $extensions;
            }
        );

        $form = $app['form.factory']->createBuilder(FormType::class, [])
            ->add('file', FileType::class, ['image_path' => 'webPath'])
            ->getForm();

        self::assertInstanceOf(Form::class, $form);
    }

    public function testFormServiceProviderWillLoadTypeExtensionsServices()
    {
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app['dummy.form.type.extension'] = function () {
            return new DummyFormTypeExtension();
        };
        $app->extend('form.type.extensions', function ($extensions) {
            $extensions[] = 'dummy.form.type.extension';

            return $extensions;
        });

        $form = $app['form.factory']
            ->createBuilder(FormType::class, [])
            ->add('file', FileType::class, ['image_path' => 'webPath'])
            ->getForm();

        self::assertInstanceOf(Form::class, $form);
    }

    public function testNonExistentTypeExtensionService()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid form type extension. The silex service \"dummy.form.type.extension\" does not exist.");
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app->extend(
            'form.type.extensions',
            function ($extensions) {
                $extensions[] = 'dummy.form.type.extension';

                return $extensions;
            }
        );

        $app['form.factory']
            ->createBuilder(FormType::class, [])
            ->add('dummy', 'dummy.form.type')
            ->getForm();
    }

    public function testFormServiceProviderWillLoadTypeGuessers()
    {
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app->extend('form.type.guessers', function ($guessers) {
            $guessers[] = new FormTypeGuesserChain([]);

            return $guessers;
        });

        self::assertInstanceOf(FormFactory::class, $app['form.factory']);
    }

    public function testFormServiceProviderWillLoadTypeGuessersServices()
    {
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app['dummy.form.type.guesser'] = function () {
            return new FormTypeGuesserChain([]);
        };
        $app->extend('form.type.guessers', function ($guessers) {
            $guessers[] = 'dummy.form.type.guesser';

            return $guessers;
        });

        self::assertInstanceOf(FormFactory::class, $app['form.factory']);
    }

    public function testNonExistentTypeGuesserService()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid form type guesser. The silex service \"dummy.form.type.guesser\" does not exist.");
        $app = new Application();

        $app->register(new FormServiceProvider());

        $app->extend(
            'form.type.guessers',
            function ($extensions) {
                $extensions[] = 'dummy.form.type.guesser';

                return $extensions;
            }
        );

        $factory = $app['form.factory'];
    }

    public function testFormServiceProviderWillUseTranslatorIfAvailable()
    {
        $app = new Application();

        $app->register(new FormServiceProvider());
        $app->register(new TranslationServiceProvider());
        $app['translator.domains'] = [
            'messages' => [
                'de' => [
                    'The CSRF token is invalid. Please try to resubmit the form.' => 'German translation',
                ],
            ],
        ];
        $app['locale'] = 'de';

        $app['csrf.token_manager'] = function () {
            return $this->getMockBuilder(CsrfTokenManagerInterface::class)->getMock();
        };

        $form = $app['form.factory']->createBuilder(FormType::class, [])
            ->getForm();

        $form->handleRequest(
            $req = Request::create(
                '/',
                'POST',
                [
                    'form' => [
                        '_token' => 'the wrong token',
                    ],
                ]
            )
        );

        self::assertFalse($form->isValid());
        $r = new ReflectionMethod($form, 'getErrors');
        if (!$r->getNumberOfParameters()) {
            self::assertStringContainsString('ERROR: German translation', $form->getErrorsAsString());
        } else {
            // as of 2.5
            self::assertStringContainsString('ERROR: German translation', (string) $form->getErrors(true, false));
        }
    }

    public function testFormServiceProviderWillNotAddNonexistentTranslationFiles()
    {
        $app = new Application([
            'locale' => 'nonexistent',
        ]);

        $app->register(new FormServiceProvider());
        $app->register(new ValidatorServiceProvider());
        $app->register(new TranslationServiceProvider(), [
            'locale_fallbacks' => [],
        ]);

        $app['form.factory'];
        $translator = $app['translator'];

        try {
            $translator->trans('test');
            $this->addToAssertionCount(1);
        } catch (NotFoundResourceException $e) {
            self::fail('Form factory should not add a translation resource that does not exist');
        }
    }

    public function testFormCsrf()
    {
        $app = new Application();
        $app->register(new FormServiceProvider());
        $app->register(new SessionServiceProvider());
        $app->register(new CsrfServiceProvider());
        $app['session.test'] = true;

        $form = $app['form.factory']->createBuilder(FormType::class, [])->getForm();

        self::assertTrue(isset($form->createView()['_token']));
    }

    public function testUserExtensionCanConfigureDefaultExtensions()
    {
        $app = new Application();
        $app->register(new FormServiceProvider());
        $app->register(new SessionServiceProvider());
        $app->register(new CsrfServiceProvider());
        $app['session.test'] = true;

        $app->extend(
            'form.type.extensions',
            function ($extensions) {
                $extensions[] = new FormServiceProviderTest\DisableCsrfExtension();

                return $extensions;
            }
        );
        $form = $app['form.factory']->createBuilder(FormType::class, [])->getForm();

        self::assertFalse($form->getConfig()->getOption('csrf_protection'));
    }
}

class DummyFormType extends AbstractType
{
}

class DummyFormTypeExtension extends AbstractTypeExtension
{
    public static function getExtendedTypes(): iterable
    {
        yield FileType::class;
    }
    
    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setDefined(['image_path']);
    }
}
