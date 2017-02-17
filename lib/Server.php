<?php

namespace Amp\Dns;

use Amp\Deferred;
use LibDNS\Decoder\Decoder;
use LibDNS\Encoder\Encoder;
use LibDNS\Messages\Message;
use LibDNS\Messages\MessageFactory;
use LibDNS\Messages\MessageTypes;

class Server
{
    const PROTOCOL_UDP = 0b01;
    const PROTOCOL_TCP = 0b10;
    const PROTOCOL_ANY = 0b11;

    private $messageFactory;
    private $encoder;
    private $decoder;

    private $udpRequestIdCounter = 1;
    private $tcpRequestIdCounter = 1;
    private $pendingUdpRequestDeferreds = [];

    /**
     * @var Deferred[]
     */
    private $pendingTcpRequestDeferreds = [];

    private $readWatcherId;
    private $writeWatcherId;
    private $connectTimeoutWatcherId;
    private $connectPromise;
    private $writeQueue = [];
    private $onWritable;
    private $socket;
    private $readBuffer = '';
    private $currentBytesRemaining;

    public $address;
    public $addressFamily;

    public $haveEstablishedUdpSocket = false;
    public $udpConnectPromise;

    public $haveEstablishedTcpSocket = false;
    public $tcpConnectFailed = false;

    public $defaultTimeout;

    public function __construct(
        $address,
        $addressFamily,
        $defaultTimeout,
        MessageFactory $messageFactory,
        Encoder $encoder,
        Decoder $decoder
    ) {
        $this->address = $address;
        $this->addressFamily = $addressFamily;
        $this->defaultTimeout = $defaultTimeout;

        $this->messageFactory = $messageFactory;
        $this->encoder = $encoder;
        $this->decoder = $decoder;
    }

    private function buildRequest($question, $id)
    {
        $request = $this->messageFactory->create(MessageTypes::QUERY);
        $request->getQuestionRecords()->add($question);

        $request->isRecursionDesired(true);
        $request->setID($id);

        return $request;
    }

    public function buildUdpRequest($question)
    {
        do {
            $id = $this->udpRequestIdCounter++;

            if ($this->udpRequestIdCounter >= MAX_REQUEST_ID) {
                $this->udpRequestIdCounter = 1;
            }
        } while (isset($this->pendingUdpRequestDeferreds[$id]));

        $this->pendingUdpRequestDeferreds[$id] = new Deferred;

        return [$this->buildRequest($question, $id), $this->pendingUdpRequestDeferreds[$id]->promise()];
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

    private function addQuestionToWriteQueue($question)
    {
        do {
            $id = $this->tcpRequestIdCounter++;

            if ($this->tcpRequestIdCounter >= MAX_REQUEST_ID) {
                $this->tcpRequestIdCounter = 1;
            }
        } while (isset($this->pendingTcpRequestDeferreds[$id]));

        $this->pendingTcpRequestDeferreds[$id] = new Deferred;

        $data = $this->encoder->encode($this->buildRequest($question, $id));
        $length = \strlen($data);
        $data = \pack('n', $length) . $data;

        $this->writeQueue[] = [$id, $data, $length + 2];

        return [$id, $this->pendingTcpRequestDeferreds[$id]->promise()];
    }

    public function sendTcpRequest($questions, $timeout)
    {
        $promises = [];
        $ids = [];

        foreach ($questions as $type => $question) {
            list($id, $promise) = $this->addQuestionToWriteQueue($question);

            $ids[$type] = $id;
            $promises[$type] = \Amp\timeout($promise, $timeout);
        }

        if (!isset($this->writeWatcherId)) {
            $this->writeWatcherId = \Amp\onWritable($this->socket, $this->onWritable);
        }

        $deferred = new Deferred;

        /** @noinspection PhpUnusedParameterInspection */
        \Amp\any($promises)
            ->when(function($null, $results) use($ids, $deferred) {
                foreach ($results[0] as $type => $error) {
                    // timed out requests will still have a pending deferred
                    unset($this->pendingTcpRequestDeferreds[$ids[$type]]);
                }

                $deferred->succeed($results[1]);
            });

        return $deferred->promise();
    }

    /**
     * @uses onConnectWritable
     */
    public function connectTcpSocket()
    {
        return $this->connectPromise === null
            ? $this->doConnect()
            : $this->connectPromise;
    }

    /**
     * @uses onReadable
     * @uses onWritable
     */
    private function doConnect()
    {
        $deferred = new Deferred;

        if(!$sock = \stream_socket_client("tcp://{$this->address}", $errNo, $errStr, 0, STREAM_CLIENT_ASYNC_CONNECT)) {
            throw new SocketException("Failed to create TCP socket for {$this->address}: {$errStr}", $errNo);
        }

        \stream_set_blocking($sock, false);

        $this->writeWatcherId = \Amp\onWritable($sock, function() use($deferred, $sock) {
            \Amp\cancel($this->writeWatcherId);
            \Amp\cancel($this->connectTimeoutWatcherId);

            $deferred->succeed();
            $this->haveEstablishedTcpSocket = true;

            $onReadable = (new \ReflectionClass($this))->getMethod('onReadable')->getClosure($this);
            $this->onWritable = (new \ReflectionClass($this))->getMethod('onWritable')->getClosure($this);

            $this->readWatcherId = \Amp\onReadable($sock, $onReadable);
            $this->writeWatcherId = $this->connectTimeoutWatcherId = $this->connectPromise = null;
        });

        $this->connectTimeoutWatcherId = \Amp\once(function() use($deferred, $sock) {
            fclose($sock);

            \Amp\cancel($this->writeWatcherId);

            $deferred->fail(new TimeoutException("TCP connection to {$this->address} failed"));
            $this->tcpConnectFailed = true;

            $this->writeWatcherId = $this->connectTimeoutWatcherId = $this->connectPromise = null;
        }, 1000); // todo: make this configurable

        $this->socket = $sock;

        return $this->connectPromise = $deferred->promise();
    }

    private function onWritable()
    {
        while (!empty($this->writeQueue)) {
            list($id, $data, $length) = $this->writeQueue[0];

            if ($length !== $written = \fwrite($this->socket, $data)) {
                if ($written === false) {
                    $this->pendingTcpRequestDeferreds[$id]->fail(new SocketException('TCP write failed'));
                    unset($this->pendingTcpRequestDeferreds[$id]);
                }

                $this->writeQueue[0] = [\substr($data, $written), $length - $written];
                return;
            }

            \array_shift($this->writeQueue);
        }

        \Amp\cancel($this->writeWatcherId);
        $this->writeWatcherId = null;
    }

    private function handleDisconnect()
    {
        $this->socket = null;
        $this->haveEstablishedTcpSocket = false;

        if ($this->readWatcherId !== null) {
            \Amp\cancel($this->readWatcherId);
            $this->readWatcherId = null;
        }

        if ($this->writeWatcherId !== null) {
            \Amp\cancel($this->writeWatcherId);
            $this->writeWatcherId = null;
        }

        foreach ($this->pendingTcpRequestDeferreds as $deferred) {
            $deferred->fail(new SocketException('Remote server disconnected'));
        }

        $this->writeQueue = $this->pendingTcpRequestDeferreds = [];
    }

    private function onReadable()
    {
        if ($this->currentBytesRemaining === null) {
            $lengthBytes = \fread($this->socket, 2);

            if ($lengthBytes === '') {
                $this->handleDisconnect();
                return;
            }

            $this->currentBytesRemaining = \current(\unpack('n', $lengthBytes));
        }

        $data = \fread($this->socket, $this->currentBytesRemaining);

        if ($data === '') {
            $this->handleDisconnect();
            return;
        }

        $receivedLength = \strlen($data);
        $this->readBuffer .= $data;

        if ($receivedLength < $this->currentBytesRemaining) {
            $this->currentBytesRemaining -= $receivedLength;
            return;
        }

        $packet = $this->readBuffer;

        $this->readBuffer = '';
        $this->currentBytesRemaining = null;

        $message = $this->decoder->decode($packet);
        $id = $message->getID();

        if (!isset($this->pendingTcpRequestDeferreds[$id])) {
            return;
        }

        $this->pendingTcpRequestDeferreds[$id]->succeed($message);
        unset($this->pendingTcpRequestDeferreds[$id]);
    }
}
