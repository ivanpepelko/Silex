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

use Swift_Mime_SimpleMessage;
use Swift_Spool;
use Swift_Transport;

use function count;

class SpoolStub implements Swift_Spool
{
    private $messages = [];
    public $hasFlushed = false;

    public function getMessages()
    {
        return $this->messages;
    }

    public function start()
    {
    }

    public function stop()
    {
    }

    public function isStarted(): bool
    {
        return count($this->messages) > 0;
    }

    public function queueMessage(Swift_Mime_SimpleMessage $message): bool
    {
        $this->messages[] = clone $message;

        return true;
    }

    public function flushQueue(Swift_Transport $transport, &$failedRecipients = null): int
    {
        $this->hasFlushed = true;
        $this->messages = [];

        return 0;
    }
}
