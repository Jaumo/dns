<?php

namespace Amp\Dns;

// @codeCoverageIgnoreStart
const MAX_REQUEST_ID = 65536;

const DEFAULT_REQUEST_TIMEOUT  = 3000;
const DEFAULT_REQUEST_ATTEMPTS = 2;
const DEFAULT_TCP_IDLE_TIMEOUT     = 15000;
const DEFAULT_TCP_CONNECT_TIMEOUT  = 5000;

const IDLE_TIMEOUT = DEFAULT_TCP_IDLE_TIMEOUT; // backwards compat, in case anyone relies on this existing
// @codeCoverageIgnoreEnd
