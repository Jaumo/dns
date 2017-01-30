<?php declare(strict_types = 1);

namespace Amp\Dns;

use Amp\Deferred;
use LibDNS\Messages\Message;
use LibDNS\Messages\MessageFactory;
use LibDNS\Messages\MessageTypes;

class Server
{
    const PROTOCOL_UDP = 0b01;
    const PROTOCOL_TCP = 0b10;
    const PROTOCOL_ANY = 0b11;

    private $messageFactory;
    private $udpRequestIdCounter;
    private $tcpRequestIdCounter;
    private $pendingUdpRequestDeferreds = [];
    private $pendingTcpRequestDeferreds = [];

    public $host;
    public $port;
    public $address;
    public $tcpSocket;
    public $haveEstablishedUdpSocket = false;
    public $udpPromise;
    public $haveEstablishedTcpSocket = false;
    public $tcpConnectFailed = false;
    public $tcpConnectPromise;

    public function __construct($address, MessageFactory $messageFactory)
    {
        $this->address = $address;
        $this->messageFactory = $messageFactory;
    }

    private function buildRequest($questions, $id)
    {
        $request = $this->messageFactory->create(MessageTypes::QUERY);

        foreach ($questions as $question) {
            $request->getQuestionRecords()->add($question);
        }

        $request->isRecursionDesired(true);
        $request->setID($id);

        return $request;
    }

    public function buildUdpRequest($questions)
    {
        do {
            $id = $this->udpRequestIdCounter++;
            if ($this->udpRequestIdCounter >= MAX_REQUEST_ID) {
                $this->udpRequestIdCounter = 1;
            }
        } while (isset($this->pendingUdpRequestDeferreds[$id]));

        $this->pendingUdpRequestDeferreds[$id] = new Deferred;

        return [$this->buildRequest($questions, $id), $this->pendingUdpRequestDeferreds[$id]->promise()];
    }

    public function finalizeUdpRequest(Message $message)
    {
        $id = $message->getID();

        if (!isset($this->pendingUdpRequestDeferreds[$id])) {
            return;
        }

        $this->pendingUdpRequestDeferreds[$id]->succeed($message);
        unset($this->pendingUdpRequestDeferreds[$id]);
    }

    public function cancelUdpRequest(Message $message)
    {
        $id = $message->getID();

        if (!isset($this->pendingUdpRequestDeferreds[$id])) {
            return;
        }

        $this->pendingUdpRequestDeferreds[$id]->fail(new RequestCancelledException);
        unset($this->pendingUdpRequestDeferreds[$id]);
    }

    public function buildTcpRequest($questions)
    {
        do {
            $id = $this->tcpRequestIdCounter++;
            if ($this->tcpRequestIdCounter >= MAX_REQUEST_ID) {
                $this->tcpRequestIdCounter = 1;
            }
        } while (isset($this->pendingTcpRequestDeferreds[$id]));

        $this->pendingTcpRequestDeferreds[$id] = new Deferred;

        return [$this->buildRequest($questions, $id), $this->pendingTcpRequestDeferreds[$id]->promise()];
    }

    public function finalizeTcpRequest(Message $message)
    {
        $id = $message->getID();

        if (!isset($this->pendingTcpRequestDeferreds[$id])) {
            return;
        }

        $this->pendingTcpRequestDeferreds[$id]->succeed($message);
        unset($this->pendingTcpRequestDeferreds[$id]);
    }

    public function cancelTcpRequest(Message $message)
    {
        $id = $message->getID();

        if (!isset($this->pendingTcpRequestDeferreds[$id])) {
            return;
        }

        $this->pendingTcpRequestDeferreds[$id]->fail(new RequestCancelledException);
        unset($this->pendingTcpRequestDeferreds[$id]);
    }
}
