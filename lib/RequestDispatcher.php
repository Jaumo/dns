<?php

namespace Amp\Dns;

use Amp\CoroutineResult;
use Amp\Deferred;
use Amp\TimeoutException as AmpTimeoutException;
use LibDNS\Decoder\Decoder;
use LibDNS\Encoder\Encoder;
use LibDNS\Messages\Message;

class RequestDispatcher
{
    private $serverManager;
    private $encoder;
    private $decoder;

    private $udpSockets = [];
    private $udpWriteQueues = [];
    private $udpWritableCallbacks = [];
    private $udpWriteWatchers = [];

    /**
     * @uses onIPv4UdpReadable
     * @uses onIPv6UdpReadable
     * @uses onUdpWritable
     */
    private function createUdpSockets()
    {
        // A single socket is use for all UDP communication (one each for IPv4 and IPv6). In order to do this, we need
        // to use stream_socket_server() instead of stream_socket_client(). With servers there's no way that I can find
        // to have the OS choose a port for us, so we do that ourselves. Since this is only ever done once, it doesn't
        // have a meaningful performance impact.

        // Try and find a port that we can bind to
        for ($port = 56211; $port > 40000; $port--) {
            if ($socket = @\stream_socket_server('udp://0.0.0.0:' . $port, $errNo, $errStr, STREAM_SERVER_BIND)) {
                $this->udpSockets[STREAM_PF_INET] = $socket;
                break;
            }
        }

        if (!$this->udpSockets[STREAM_PF_INET]) {
            throw new SocketConnectFailedException('Error creating UDP socket for IPv4 communication');
        }

        \stream_set_blocking($this->udpSockets[STREAM_PF_INET], false);
        \Amp\onReadable($this->udpSockets[STREAM_PF_INET], $this->makePrivateCallable('onIPv4UdpReadable'));
        $this->udpWritableCallbacks[STREAM_PF_INET] = function() { $this->onUdpWritable(STREAM_PF_INET); };

        // Don't throw if we can't create an IPv6 socket, as some machines may not support it
        if ($socket = @\stream_socket_server('udp://[::]:' . $port, $errNo, $errStr, STREAM_SERVER_BIND) ?: null) {
            $this->udpSockets[STREAM_PF_INET6] = $socket;
            \stream_set_blocking($this->udpSockets[STREAM_PF_INET6], false);
            \Amp\onReadable($this->udpSockets[STREAM_PF_INET6], $this->makePrivateCallable('onIPv6UdpReadable'));
            $this->udpWritableCallbacks[STREAM_PF_INET6] = function() { $this->onUdpWritable(STREAM_PF_INET6); };
        }
    }

    private function sendQuestionsToServerOverUdp(Server $server, $questions, $options)
    {
        // make sure only one packet is sent until we get the first response
        if ($server->udpConnectPromise !== null) {
            yield $server->udpConnectPromise;
        } else if (!$server->haveEstablishedUdpSocket) {
            $deferred = new Deferred;
            $server->udpConnectPromise = $deferred->promise();
        }

        reset($questions);
        $firstKey = key($questions);
        $firstQuestion = $questions[$firstKey];
        unset($questions[$firstKey]);

        list($request, $promise) = $server->buildUdpRequest($firstQuestion);
        $this->enqueueUdpMessageForSending($request, $server);

        $responses = [];

        try {
            $timeout = !empty($options['timeout'])
                ? (int)$options['timeout']
                : $server->defaultRequestTimeout;

            $responses[$firstKey] = (yield \Amp\timeout($promise, $timeout));
        } catch (AmpTimeoutException $e) {
            $server->cancelUdpRequest($request);

            $e = new TimeoutException('Request timed out after ' . $timeout . 'ms');

            if (isset($deferred)) {
                $deferred->fail($e);
            }

            throw $e;
        }

        if (isset($deferred)) {
            $deferred->succeed();
            $server->haveEstablishedUdpSocket = true;
            $server->udpConnectPromise = null;
        }

        $promises = [];

        foreach ($questions as $key => $question) {
            list($request, $promise) = $server->buildUdpRequest($question);

            $this->enqueueUdpMessageForSending($request, $server);
            $promises[$key] = $promise;
        }

        try {
            $responses = array_merge($responses, (yield \Amp\timeout(\Amp\all($promises), $timeout)));
        } catch (AmpTimeoutException $e) {
            $server->cancelUdpRequest($request);
            throw new TimeoutException('Request timed out after ' . $timeout . 'ms');
        }

        yield new CoroutineResult($responses);
    }

    private function sendQuestionsToServerOverTcp(Server $server, $questions, $options)
    {
        if ($server->tcpConnectFailed) {
            throw new ResolutionException("TCP failed to connect for {$server->address}");
        }

        if (!$server->haveEstablishedTcpSocket) {
            yield $server->connectTcpSocket($options);
        }

        $timeout = !empty($options['timeout'])
            ? (int)$options['timeout']
            : $server->defaultRequestTimeout;

        $responses = (yield $server->sendTcpRequest($questions, $timeout));

        yield new CoroutineResult($responses);
    }


    private function sendQuestionsToServerOverTcpWithUdpFallback(Server $server, $questions, $options)
    {
        try {
            $responses = (yield \Amp\resolve($this->sendQuestionsToServerOverTcp($server, $questions, $options)));
        } catch (\Exception $e) {
            $responses = (yield \Amp\resolve($this->sendQuestionsToServerOverUdp($server, $questions, $options)));
        }

        yield new CoroutineResult($responses);
    }

    private function sendQuestionsToServerOverUdpWithTcpFallback(Server $server, $questions, $options)
    {
        $responses = [];

        try {
            $responses = (yield \Amp\resolve($this->sendQuestionsToServerOverUdp($server, $questions, $options)));

            if (!$server->haveEstablishedTcpSocket && !$server->tcpConnectFailed) {
                // we know the server is there, try and initiate a TCP connection we can use for future requests
                // but don't wait for it, we don't need it right now
                $server->connectTcpSocket($options);
            }
        } catch (SocketConnectFailedException $e) {
            // ignore this, we have the results we need already
        } catch (\Exception $e) {
            $responses = (yield \Amp\resolve($this->sendQuestionsToServerOverTcp($server, $questions, $options)));
        }

        yield new CoroutineResult($responses);
    }

    private function onIPv4UdpReadable()
    {
        $packet = \stream_socket_recvfrom($this->udpSockets[STREAM_PF_INET], 1024, 0, $address);

        $this->serverManager->getServerByAddress($address)
            ->finalizeSuccessfulUdpRequest($this->decoder->decode($packet));
    }

    private function onIPv6UdpReadable()
    {
        $packet = \stream_socket_recvfrom($this->udpSockets[STREAM_PF_INET6], 1024, 0, $address);

        $portPos = \strrpos($address, ':');
        $address = '[' . \substr($address, 0, $portPos) . ']' . \substr($address, $portPos);

        $this->serverManager->getServerByAddress($address)
            ->finalizeSuccessfulUdpRequest($this->decoder->decode($packet));
    }

    private function onUdpWritable($addressFamily)
    {
        while ($this->udpWriteQueues[$addressFamily]) {
            /** @var Server $server */
            list($data, $length, $messageId, $server) = $this->udpWriteQueues[$addressFamily][0];

            if (\stream_socket_sendto($this->udpSockets[$addressFamily], $data, 0, $server->address) !== $length) {
                $server->finalizeFailedUdpRequest($messageId, new SocketWriteFailedException('UDP write failed'));
                return;
            }

            \array_shift($this->udpWriteQueues[$addressFamily]);
        }

        \Amp\cancel($this->udpWriteWatchers[$addressFamily]);
        $this->udpWriteWatchers[$addressFamily] = null;
    }

    private function enqueueUdpMessageForSending(Message $message, Server $server)
    {
        $addressFamily = $server->addressFamily;
        $data = $this->encoder->encode($message);
        $length = \strlen($data);

        $this->udpWriteQueues[$addressFamily][] = [$data, $length, $message->getID(), $server];

        if (!isset($this->udpWriteWatchers[$addressFamily])) {
            $this->udpWriteWatchers[$addressFamily] = \Amp\onWritable(
                $this->udpSockets[$addressFamily],
                $this->udpWritableCallbacks[$addressFamily]
            );
        }
    }

    private function makePrivateCallable($method)
    {
        return (new \ReflectionClass($this))->getMethod($method)->getClosure($this);
    }

    public function __construct(ServerManager $serverManager, Encoder $encoder, Decoder $decoder)
    {
        $this->serverManager = $serverManager;
        $this->encoder = $encoder;
        $this->decoder = $decoder;

        $this->createUdpSockets();
    }

    public function sendQuestionsToServer(Server $server, $protocols, $questions, $options)
    {
        // not allowed to use TCP, just go straight to UDP and give up on failure
        if (!($protocols & Server::PROTOCOL_TCP)) {
            return \Amp\resolve($this->sendQuestionsToServerOverUdp($server, $questions, $options));
        }

        // not allowed to use UDP, just go straight to TCP and give up on failure
        if (!($protocols & Server::PROTOCOL_UDP)) {
            return \Amp\resolve($this->sendQuestionsToServerOverTcp($server, $questions, $options));
        }

        // tried and failed to connect TCP, just go straight to UDP and give up on failure
        if ($server->tcpConnectFailed) {
            return \Amp\resolve($this->sendQuestionsToServerOverUdp($server, $questions, $options));
        }

        // already have a TCP connection, try and use it but fall back to UDP
        if ($server->haveEstablishedTcpSocket) {
            return \Amp\resolve($this->sendQuestionsToServerOverTcpWithUdpFallback($server, $questions, $options));
        }

        // waiting for a TCP connect to complete or no sockets yet, try UDP first then TCP
        return \Amp\resolve($this->sendQuestionsToServerOverUdpWithTcpFallback($server, $questions, $options));
    }

    public function haveIPv6Support()
    {
        return isset($this->udpSockets[STREAM_PF_INET6]);
    }
}
