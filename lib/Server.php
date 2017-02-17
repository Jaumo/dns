<?php

namespace Amp\Dns;

use Amp\Deferred;
use Amp\Pause;
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

    const OP_IS_SYSTEM_SERVER = 'is_system_server';

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
    private $idleTimeoutWatcherId;
    private $connectPromise;
    private $writeQueue = [];
    private $onWritable;
    private $socket;
    private $readBuffer = '';
    private $currentBytesRemaining;

    public $isSystemServer;

    public $address;
    public $addressFamily;

    public $haveEstablishedUdpSocket = false;
    public $udpConnectPromise;

    public $haveEstablishedTcpSocket = false;
    public $tcpConnectFailed = false;
    public $tcpConnectTimeout;
    public $tcpIdleTimeout;

    public $defaultRequestTimeout;

    public function __construct(
        $address,
        $addressFamily,
        array $options,
        MessageFactory $messageFactory,
        Encoder $encoder,
        Decoder $decoder
    ) {
        $this->address = $address;
        $this->addressFamily = $addressFamily;

        $this->isSystemServer        = $options[Server::OP_IS_SYSTEM_SERVER];
        $this->defaultRequestTimeout = $options[Option::REQUEST_TIMEOUT];
        $this->tcpConnectTimeout     = $options[Option::TCP_CONNECT_TIMEOUT];
        $this->tcpIdleTimeout        = $options[Option::TCP_IDLE_TIMEOUT];

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

    public function finalizeSuccessfulUdpRequest(Message $message)
    {
        $id = $message->getID();

        if (!isset($this->pendingUdpRequestDeferreds[$id])) {
            return;
        }

        $this->pendingUdpRequestDeferreds[$id]->succeed($message);
        unset($this->pendingUdpRequestDeferreds[$id]);
    }

    public function finalizeFailedUdpRequest($id, \Exception $error)
    {
        if (!isset($this->pendingUdpRequestDeferreds[$id])) {
            return;
        }

        $this->pendingUdpRequestDeferreds[$id]->fail($error);
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
            $this->onSocketActivity(); // do this here to stop timeout kicking in before socket becomes writable
            $this->writeWatcherId = \Amp\onWritable($this->socket, $this->onWritable);
        }

        $deferred = new Deferred;

        \Amp\some($promises)
            ->when(function($error, $results) use($ids, $deferred, $timeout) {
                if ($error) {
                    foreach ($ids as $type => $id) {
                        // timed out requests will still have a pending deferred
                        unset($this->pendingTcpRequestDeferreds[$id]);
                    }

                    $deferred->fail(new ResolutionException('All requests failed'));
                    return;
                }

                foreach ($results[0] as $type => $ex) {
                    // timed out requests will still have a pending deferred
                    unset($this->pendingTcpRequestDeferreds[$ids[$type]]);
                }

                $deferred->succeed($results[1]);
            });

        return $deferred->promise();
    }

    /**
     * @uses onConnectWritable
     * @param array $options
     * @return \Amp\Promise
     */
    public function connectTcpSocket(array $options)
    {
        return $this->connectPromise === null
            ? $this->doConnect($options)
            : $this->connectPromise;
    }

    /**
     * @uses onTcpReadable
     * @uses onTcpWritable
     * @param array $options
     * @return \Amp\Promise
     */
    private function doConnect(array $options)
    {
        $deferred = new Deferred;

        if(!$sock = \stream_socket_client("tcp://{$this->address}", $errNo, $errStr, 0, STREAM_CLIENT_ASYNC_CONNECT)) {
            $e = new SocketConnectFailedException("Failed to create TCP socket for {$this->address}: {$errStr}", $errNo);
            $deferred->fail($e);
            throw $e;
        }

        \stream_set_blocking($sock, false);

        $this->writeWatcherId = \Amp\onWritable($sock, function() use($deferred, $sock) {
            \Amp\cancel($this->writeWatcherId);
            \Amp\cancel($this->connectTimeoutWatcherId);

            $deferred->succeed();
            $this->haveEstablishedTcpSocket = true;

            $onReadable = (new \ReflectionClass($this))->getMethod('onTcpReadable')->getClosure($this);
            $this->onWritable = (new \ReflectionClass($this))->getMethod('onTcpWritable')->getClosure($this);

            $this->readWatcherId = \Amp\onReadable($sock, $onReadable);
            $this->writeWatcherId = $this->connectTimeoutWatcherId = $this->connectPromise = null;
        });

        $connectTimeout = !empty($options[Option::TCP_CONNECT_TIMEOUT])
            ? (int)$options[Option::TCP_CONNECT_TIMEOUT]
            : $this->tcpConnectTimeout;

        $this->connectTimeoutWatcherId = \Amp\once(function() use($deferred, $sock) {
            \fclose($sock);

            \Amp\cancel($this->writeWatcherId);

            $deferred->fail(new SocketConnectFailedException("TCP connection to {$this->address} failed"));
            $this->tcpConnectFailed = true;

            $this->writeWatcherId = $this->connectTimeoutWatcherId = $this->connectPromise = null;
        }, $connectTimeout);

        $this->socket = $sock;

        return $this->connectPromise = $deferred->promise();
    }

    private function cleanUpAfterSocketDisconnectOrIdleTimeout()
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

    private function attemptToGracefullyDestroyTcpSocket($socket)
    {
        $done = false;

        $watcherId = \Amp\onReadable($socket, function($watcherId, $socket) use(&$done) {
            $result = @\fread($socket, 1024);

            if ($result === '') {
                \Amp\cancel($watcherId);
                $done = true;
                @\fclose($socket);
            } else if ($result === false) {
                \Amp\cancel($watcherId);
                $done = true;
            }
        });

        \stream_socket_shutdown($socket, STREAM_SHUT_WR);
        yield new Pause(3000);

        if (!$done) {
            \Amp\cancel($watcherId);
            @\fclose($socket);
        }
    }

    private function onSocketActivity()
    {
        if (isset($this->idleTimeoutWatcherId)) {
            \Amp\cancel($this->idleTimeoutWatcherId);
        }

        $this->idleTimeoutWatcherId = \Amp\once(function() {
            $socket = $this->socket;

            $this->cleanUpAfterSocketDisconnectOrIdleTimeout();
            \Amp\resolve($this->attemptToGracefullyDestroyTcpSocket($socket));
        }, $this->tcpIdleTimeout);
    }

    private function onTcpWritable()
    {
        $this->onSocketActivity();

        while (!empty($this->writeQueue)) {
            list($id, $data, $length) = $this->writeQueue[0];

            if ($length !== $written = \fwrite($this->socket, $data)) {
                if ($written === false) {
                    $this->pendingTcpRequestDeferreds[$id]->fail(new SocketWriteFailedException('TCP write failed'));
                    unset($this->pendingTcpRequestDeferreds[$id]);
                }

                $this->writeQueue[0] = [\substr($data, $written), $length - $written];
                return;
            }

            \array_shift($this->writeQueue);
        }

        if (isset($this->idleTimeoutWatcherId)) {
            \Amp\cancel($this->idleTimeoutWatcherId);
        }

        \Amp\cancel($this->writeWatcherId);
        $this->writeWatcherId = null;
    }

    private function onTcpReadable()
    {
        if ($this->currentBytesRemaining === null) {
            $lengthBytes = \fread($this->socket, 2);

            if ($lengthBytes === '') {
                $this->cleanUpAfterSocketDisconnectOrIdleTimeout();
                return;
            }

            $this->currentBytesRemaining = \current(\unpack('n', $lengthBytes));
        }

        $data = \fread($this->socket, $this->currentBytesRemaining);

        if ($data === '') {
            $this->cleanUpAfterSocketDisconnectOrIdleTimeout();
            return;
        }

        $this->onSocketActivity();

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
