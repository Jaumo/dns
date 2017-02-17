<?php

namespace Amp\Dns;

final class Option
{
    const REQUEST_TIMEOUT = 'request_timeout';
    const REQUEST_ATTEMPTS = 'request_attempts'; // TODO: Respect this setting
    const TCP_CONNECT_TIMEOUT = 'tcp_connect_timeout';
    const TCP_IDLE_TIMEOUT = 'tcp_idle_timeout';

    private function __construct() {}
}
