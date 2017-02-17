<?php

namespace Amp\Dns;

use LibDNS\Decoder\Decoder;
use LibDNS\Encoder\Encoder;
use LibDNS\Messages\MessageFactory;

class ServerManager
{
    private $encoder;
    private $decoder;

    private $servers = [];

    public function __construct(Encoder $encoder, Decoder $decoder)
    {
        $this->encoder = $encoder;
        $this->decoder = $decoder;
        $this->messageFactory = new MessageFactory;
    }

    public function createOrRetrieveServer($address, $addressFamily, $options)
    {
        if (!isset($this->servers[$address])) {
            $this->servers[$address] = new Server(
                $address, $addressFamily, $options,
                $this->messageFactory, $this->encoder, $this->decoder
            );
        }

        return $this->servers[$address];
    }

    public function getServerByAddress($address)
    {
        return isset($this->servers[$address])
            ? $this->servers[$address]
            : null;
    }
}
