<?php declare(strict_types = 1);

namespace Amp\Dns;

use Amp\Deferred;
use Amp\TimeoutException as AmpTimeoutException;
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

    private $udpRequestIdCounter = 0;
    private $tcpRequestIdCounter = 0;
    private $pendingUdpRequestDeferreds = [];
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

    public function __construct($address, $addressFamily, MessageFactory $messageFactory, Encoder $encoder, Decoder $decoder)
    {
        $this->address = $address;
        $this->addressFamily = $addressFamily;

        $this->messageFactory = $messageFactory;
        $this->encoder = $encoder;
        $this->decoder = $decoder;
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

    public function sendTcpRequest($questions, $timeout)
    {
        do {
            $id = $this->tcpRequestIdCounter++;
            if ($this->tcpRequestIdCounter >= MAX_REQUEST_ID) {
                $this->tcpRequestIdCounter = 1;
            }
        } while (isset($this->pendingTcpRequestDeferreds[$id]));

        $this->pendingTcpRequestDeferreds[$id] = new Deferred;

        $data = $this->encoder->encode($this->buildRequest($questions, $id));
        $length = \strlen($data);

        $data = \pack('n', $length) . $data;
        $length += 2;

        if (\fwrite($this->socket, $data) !== $length) {
            $this->writeQueue[] = [$data, $length];

            if (!isset($this->writeWatcherId)) {
                $this->writeWatcherId = \Amp\onWritable($this->socket, $this->onWritable);
            }
        }

        return \Amp\timeout($this->pendingTcpRequestDeferreds[$id]->promise(), $timeout)
            ->when(function($error) use($id, $timeout) {
                if ($error instanceof AmpTimeoutException) {
                    $this->pendingTcpRequestDeferreds[$id]->fail($error);
                }
            });
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

        $this->connectTimeoutWatcherId = \Amp\once(function() use($deferred) {
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
            list($data, $length) = $this->writeQueue[0];

            if (\fwrite($this->socket, $data) !== $length) {
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

        if ($receivedLength < $this->currentBytesRemaining) {
            $this->readBuffer .= $data;
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
