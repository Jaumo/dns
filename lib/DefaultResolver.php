<?php

namespace Amp\Dns;

use Amp\Cache\ArrayCache;
use Amp\Cache\Cache;
use Amp\CombinatorException;
use Amp\CoroutineResult;
use Amp\Deferred;
use Amp\Failure;
use Amp\File\FilesystemException;
use Amp\Success;
use Amp\TimeoutException as AmpTimeoutException;
use Amp\WindowsRegistry\KeyNotFoundException;
use Amp\WindowsRegistry\WindowsRegistry;
use LibDNS\Decoder\DecoderFactory;
use LibDNS\Encoder\EncoderFactory;
use LibDNS\Messages\MessageFactory;
use LibDNS\Messages\MessageTypes;
use LibDNS\Records\QuestionFactory;

class DefaultResolver implements Resolver
{
    const RESOLV_CONF_PATH = '/etc/resolv.conf';
    const HOSTS_FILE_PATH = '/etc/hosts';
    const HOSTS_FILE_PATH_WIN = 'C:\Windows\system32\drivers\etc\hosts';

    private $defaultServerConfig = [
        "nameservers" => [
            "8.8.8.8:53",
            "8.8.4.4:53",
        ],
        "timeout" => 3000,
        "attempts" => 2,
    ];

    private static $isWindows;

    private $messageFactory;
    private $questionFactory;
    private $encoder;
    private $decoder;
    private $cache;
    private $requestIdCounter;
    private $pendingRequests;
    private $serverIdMap;
    private $serverUriMap;
    private $serverIdTimeoutMap;
    private $now;
    private $serverTimeoutWatcher;
    private $systemServerConfig;
    private $systemServerConfigLoadPromise;
    private $hostsFileData;
    private $hostsFileLoadPromise;
    private $udpSocket;
    private $defaultServerList = [];

    /** @var Server[] */
    private $servers = [];

    private function getServer($address)
    {
        if (!isset($this->servers[$address])) {
            $this->servers[$address] = new Server($address, $this->messageFactory);
        }

        return $this->servers[$address];
    }

    public function __construct(Cache $cache = null)
    {
        $this->messageFactory = new MessageFactory;
        $this->questionFactory = new QuestionFactory;
        $this->encoder = (new EncoderFactory)->create();
        $this->decoder = (new DecoderFactory)->create();
        $this->cache = isset($cache) ? $cache : new ArrayCache;
        $this->requestIdCounter = 1;
        $this->pendingRequests = [];
        $this->serverIdMap = [];
        $this->serverUriMap = [];
        $this->serverIdTimeoutMap = [];
        $this->now = \time();
        $this->serverTimeoutWatcher = \Amp\repeat(function ($watcherId) {
            $this->now = $now = \time();
            foreach ($this->serverIdTimeoutMap as $id => $expiry) {
                if ($now > $expiry) {
                    $this->unloadServer($id);
                }
            }
            if (empty($this->serverIdMap)) {
                \Amp\disable($watcherId);
            }
        }, 1000, $options = [
            "enable" => true,
            "keep_alive" => false,
        ]);
        self::$isWindows = \stripos(PHP_OS, "win") === 0;
    }

    /**
     * {@inheritdoc}
     */
    public function resolve($name, array $options = [])
    {
        if ($inAddr = @\inet_pton($name)) {
            return new Success([[$name, isset($inAddr[4]) ? Record::AAAA : Record::A, $ttl = null]]);
        }

        if (!\Amp\Dns\isValidHostName($name)) {
            return new Failure(new ResolutionException('Cannot resolve; invalid host name'));
        }

        $types = [];

        foreach (empty($options['types']) ? [Record::A, Record::AAAA] : (array)$options['types'] as $type) {
            if ($type !== Record::A && $type !== Record::AAAA) {
                return new Failure(new ResolutionException(
                    'resolve() may only be used to lookup A and AAAA records, use query() for advanced lookups'
                ));
            }

            $types[$type] = $type;
        }

        return $this->flattenResults(\Amp\resolve($this->resolveName(strtolower($name), $types, $options)), $types);
    }

    /**
     * {@inheritdoc}
     */
    public function query($name, $type, array $options = [])
    {
        return $this->flattenResults(\Amp\resolve(
            empty($options['recurse'])
                ? $this->doResolve(strtolower($name), [$type], $options)
                : $this->doRecurse(strtolower($name), [$type], $options)
        ), [$type]);
    }

    private function resolveName($name, $types, $options)
    {
        $records = [];
        $promises = [];
        $haveRecords = false;

        foreach ($types as $type) {
            $promises[$type] = \Amp\resolve($this->resolveNameLocally($name, $type, $options));
        }

        foreach ((yield \Amp\all($promises)) as $type => $result) {
            if ($result !== null) {
                $haveRecords = !empty($records[$type] = $result) || $haveRecords;
                unset($types[$type]);
            }
        }

        if (empty($types)) {
            if (!$haveRecords) {
                throw new NoRecordException("No records returned for {$name} (cached result)");
            }

            yield new CoroutineResult($records);
            return;
        }

        $questions = [];

        foreach ($types as $type) {
            $question = $this->questionFactory->create($type);
            $question->setName($name);
            $questions[$type] = $question;
        }

        foreach ((yield $this->getServerListForRequest($options)) as $serverInfo) {
            $result = (yield \Amp\resolve($this->sendQuestionsToServer($serverInfo[0], $serverInfo[1], $questions, $options)));

            foreach ($result as $type => $recordSet) {

            }
        }
    }

    private function sendQuestionsToServer(Server $server, $protocols, $questions, $options)
    {
        // not allowed to use TCP, just go straight to UDP and give up on failure
        if (!($protocols & Server::PROTOCOL_TCP)) {
            return $this->sendQuestionsToServerOverUdp($server, $questions, $options);
        }

        // not allowed to use UDP, just go straight to TCP and give up on failure
        if (!($protocols & Server::PROTOCOL_UDP)) {
            return $this->sendQuestionsToServerOverTcp($server, $questions, $options);
        }

        // tried and failed to connect TCP, just go straight to UDP and give up on failure
        if ($server->tcpConnectFailed) {
            return $this->sendQuestionsToServerOverUdp($server, $questions, $options);
        }

        // already have a TCP connection, try and use it but fall back to UDP
        if ($server->haveEstablishedTcpSocket) {
            return $this->sendQuestionsToServerOverTcpWithUdpFallback($server, $questions, $options);
        }

        // waiting for a TCP connect to complete or no sockets yet, try UDP first then TCP
        return $this->sendQuestionsToServerOverUdpWithTcpFallback($server, $questions, $options);
    }

    public function sendQuestionsToServerOverTcp(Server $server, $questions, $options)
    {
        // todo
    }

    public function sendQuestionsToServerOverTcpWithUdpFallback(Server $server, $questions, $options)
    {
        // todo
    }

    public function sendQuestionsToServerOverUdp(Server $server, $questions, $options)
    {
        // make sure only one packet is sent until we get the first response
        if ($server->udpPromise !== null) {
            yield $server->udpPromise;
        } else if (!$server->haveEstablishedUdpSocket) {
            $deferred = new Deferred;
            $server->udpPromise = $deferred->promise();
        }

        list($request, $promise) = $server->buildUdpRequest($questions);

        $socket = $this->getUdpSocket();
        \stream_socket_sendto($socket, $this->encoder->encode($request), 0, $server->address);

        try {
            $timeout = empty($options['timeout'])
                ? $this->systemServerConfig['timeout']
                : (int)$options['timeout'];

            $response = (yield \Amp\timeout($promise, $timeout));
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
            $server->udpPromise = null;
        }

        yield new CoroutineResult($response);
    }

    public function sendQuestionsToServerOverUdpWithTcpFallback(Server $server, $questions, $options)
    {
        try {
            $result = (yield \Amp\resolve($this->sendQuestionsToServerOverUdp($server, $questions, $options)));

            if ($server->tcpSocket === null && !$server->tcpConnectFailed) {
                // we know the server is there, try and initiate a TCP connection we can use for future requests
                // but don't wait for it, we don't need it right now
                $this->setUpTcpSocket($server);
            }

            yield new CoroutineResult($result);
            return;
        } catch (\Exception $e) {
            // todo
        }
    }

    public function setUpTcpSocket(Server $server)
    {
        if ($server->tcpConnectPromise !== null) {
            yield $server->tcpConnectPromise;
            return;
        }

        $deferred = new Deferred;
    }

    /**
     * @uses onUdpReadable
     */
    private function getUdpSocket()
    {
        if ($this->udpSocket === null) {
            // single socket used for all UDP communication, use fake remote address
            $this->udpSocket = stream_socket_client('udp://11.11.11.11:11', $errNo, $errStr);
            \Amp\onReadable($this->udpSocket, $this->makePrivateCallable('onUdpReadable'));
        }

        return $this->udpSocket;
    }

    private function onUdpReadable()
    {
        $packet = \stream_socket_recvfrom($this->udpSocket, 1024, 0, $address);

        $portPos = \strrpos($address, ':');
        if (\strpos($address, ':') !== $portPos) {
            // ipv6 addresses returned by recvfrom are not wrapped in []
            $address = '[' . \substr($address, 0, $portPos) . ']' . \substr($address, $portPos);
        }

        $this->servers[$address]->finalizeUdpRequest($this->decoder->decode($packet));
    }

    private function getServerListForRequest($options)
    {
        if (!empty($options['server'])) {
            try {
                return new Success([$this->parseCustomServerUri($options['server'])]);
            } catch (\Exception $e) {
                return new Failure($e);
            }
        }

        if (isset($this->systemServerConfig)) {
            return new Success($this->defaultServerList);
        }

        $deferred = new Deferred;

        $this->loadSystemServerConfig()->when(function($error, $result) use($deferred) {
            if ($error) {
                $deferred->fail($error);
            } else if (empty($result['nameservers'])) {
                $deferred->fail(new ResolutionException('No nameserver specified in system config'));
            } else {
                $this->systemServerConfig = $result;

                foreach ($result['nameservers'] as $host) {
                    $this->defaultServerList[] = [$this->getServer("{$host}:53"), Server::PROTOCOL_ANY];
                }

                $deferred->succeed($this->defaultServerList);
            }
        });

        return $deferred->promise();
    }

    private function resolveNameLocally($name, $type, $options)
    {
        // Check hosts file
        if (!isset($options["hosts"]) || $options["hosts"]) {
            $result = (yield \Amp\resolve($this->lookupNameInHostsFile($name, $type, !empty($options["reload_hosts"]))));

            if (!empty($result)) {
                yield new CoroutineResult($result);
                return;
            }
        }

        $result = null;

        // Check cache
        if (!isset($options["cache"]) || $options["cache"]) {
            $result = (yield $this->cache->get("$name#$type"));
        }

        yield new CoroutineResult($result);
    }

    private function lookupNameInHostsFile($name, $type, $reload)
    {
        if (!isset($this->hostsFileData) || $reload) {
            $this->hostsFileData = (yield $this->loadHostsFile());
        }

        yield new CoroutineResult(
            isset($this->hostsFileData[$type][$name])
                ? [$this->hostsFileData[$type][$name], $type, $ttl = null]
                : null
        );
    }

    // flatten $result while preserving order according to $types (append unspecified types for e.g. Record::ALL queries)
    private function flattenResults($promise, array $types) {
        return \Amp\pipe($promise, function (array $result) use ($types) {
            $retval = [];
            foreach ($types as $type) {
                if (isset($result[$type])) {
                    $retval = \array_merge($retval, $result[$type]);
                    unset($result[$type]);
                }
            }
            return $result ? \array_merge($retval, \call_user_func_array("array_merge", $result)) : $retval;
        });
    }

    private function doRecurse($name, array $types, $options) {
        if (array_intersect($types, [Record::CNAME, Record::DNAME])) {
            throw new ResolutionException("Cannot use recursion for CNAME and DNAME records");
        }

        $types = array_merge($types, [Record::CNAME, Record::DNAME]);
        $lookupName = $name;
        for ($i = 0; $i < 30; $i++) {
            $result = (yield \Amp\resolve($this->doResolve($lookupName, $types, $options)));
            if (count($result) > isset($result[Record::CNAME]) + isset($result[Record::DNAME])) {
                unset($result[Record::CNAME], $result[Record::DNAME]);
                yield new CoroutineResult($result);
                return;
            }
            // @TODO check for potentially using recursion and iterate over *all* CNAME/DNAME
            // @FIXME check higher level for CNAME?
            foreach ([Record::CNAME, Record::DNAME] as $type) {
                if (isset($result[$type])) {
                    list($lookupName) = $result[$type][0];
                }
            }
        }

        throw new ResolutionException("CNAME or DNAME chain too long (possible recursion?)");
    }

    private function doRequest($uri, $name, $type) {
        $server = $this->loadExistingServer($uri) ?: $this->loadNewServer($uri);

        $useTCP = substr($uri, 0, 6) == "tcp://";
        if ($useTCP && isset($server->connect)) {
            return \Amp\pipe($server->connect, function() use ($uri, $name, $type) {
                return $this->doRequest($uri, $name, $type);
            });
        }

        // Get the next available request ID
        do {
            $requestId = $this->requestIdCounter++;
            if ($this->requestIdCounter >= MAX_REQUEST_ID) {
                $this->requestIdCounter = 1;
            }
        } while (isset($this->pendingRequests[$requestId]));

        // Create question record
        $question = $this->questionFactory->create($type);
        $question->setName($name);

        // Create request message
        $request = $this->messageFactory->create(MessageTypes::QUERY);
        $request->getQuestionRecords()->add($question);
        $request->isRecursionDesired(true);
        $request->setID($requestId);

        // Encode request message
        $requestPacket = $this->encoder->encode($request);

        if ($useTCP) {
            $requestPacket = pack("n", strlen($requestPacket)) . $requestPacket;
        }

        // Send request
        $bytesWritten = \fwrite($server->socket, $requestPacket);
        if ($bytesWritten === false || isset($packet[$bytesWritten])) {
            throw new ResolutionException(
                "Request send failed"
            );
        }

        $promisor = new Deferred;
        $server->pendingRequests[$requestId] = true;
        $this->pendingRequests[$requestId] = [$promisor, $name, $type, $uri];

        return $promisor->promise();
    }

    private function doResolve($name, array $types, $options) {
        if (!$this->systemServerConfig) {
            $this->systemServerConfig = (yield \Amp\resolve($this->loadSystemServerConfig()));
        }

        if (empty($types)) {
            yield new CoroutineResult([]);
            return;
        }

        assert(array_reduce($types, function ($result, $val) { return $result && \is_int($val); }, true), 'The $types passed to DNS functions must all be integers (from \Amp\Dns\Record class)');

        $name = \strtolower($name);
        $result = [];

        // Check for cache hits
        if (!isset($options["cache"]) || $options["cache"]) {
            foreach ($types as $k => $type) {
                $cacheKey = "$name#$type";
                $cacheValue = (yield $this->cache->get($cacheKey));

                if ($cacheValue !== null) {
                    $result[$type] = $cacheValue;
                    unset($types[$k]);
                }
            }
            if (empty($types)) {
                if (empty(array_filter($result))) {
                    throw new NoRecordException("No records returned for {$name} (cached result)");
                } else {
                    yield new CoroutineResult($result);
                    return;
                }
            }
        }

        $timeout = empty($options["timeout"]) ? $this->systemServerConfig["timeout"] : (int) $options["timeout"];

        if (empty($options["server"])) {
            if (empty($this->systemServerConfig["nameservers"])) {
                throw new ResolutionException("No nameserver specified in system config");
            }

            $uri = "udp://" . $this->systemServerConfig["nameservers"][0];
        } else {
            $uri = $this->parseCustomServerUri($options["server"]);
        }

        $promises = [];

        foreach ($types as $type) {
            $promises[] = $this->doRequest($uri, $name, $type);
        }

        try {
            list( , $resultArr) = (yield \Amp\timeout(\Amp\some($promises), $timeout));
            foreach ($resultArr as $value) {
                $result += $value;
            }
        } catch (TimeoutException $e) {
            if (substr($uri, 0, 6) == "tcp://") {
                throw new TimeoutException(
                    "Name resolution timed out for {$name}"
                );
            } else {
                $options["server"] = \preg_replace("#[a-z.]+://#", "tcp://", $uri);
                yield new CoroutineResult(\Amp\resolve($this->doResolve($name, $types, $options)));
                return;
            }
        } catch (ResolutionException $e) {
            if (empty($result)) { // if we have no cached results
                throw $e;
            }
        } catch (CombinatorException $e) { // if all promises in Amp\some fail
            if (empty($result)) { // if we have no cached results
                foreach ($e->getExceptions() as $ex) {
                    if ($ex instanceof NoRecordException) {
                        throw new NoRecordException("No records returned for {$name}", 0, $e);
                    }
                }
                throw new ResolutionException("All name resolution requests failed", 0, $e);
            }
        }

        yield new CoroutineResult($result);
    }

    /** @link http://man7.org/linux/man-pages/man5/resolv.conf.5.html */
    private function loadResolvConf($path)
    {
        $result = $this->defaultServerConfig;

        try {
            $lines = explode("\n", (yield \Amp\File\get($path)));
            $result["nameservers"] = [];

            foreach ($lines as $line) {
                $line = \preg_split('#\s+#', $line, 2);

                if (\count($line) !== 2) {
                    continue;
                }

                list($type, $value) = $line;

                if ($type === "nameserver") {
                    $line[1] = trim($line[1]);
                    $ip = @\inet_pton($line[1]);

                    if ($ip === false) {
                        continue;
                    }

                    if (isset($ip[15])) {
                        $result["nameservers"][] = "[" . $line[1] . "]:53";
                    } else {
                        $result["nameservers"][] = $line[1] . ":53";
                    }
                } else if ($type === "options") {
                    $optline = preg_split('#\s+#', $value, 2);
                    if (\count($optline) !== 2) {
                        continue;
                    }

                    // TODO: Respect the contents of the attempts setting during resolution

                    list($option, $value) = $optline;
                    if (in_array($option, ["timeout", "attempts"])) {
                        $result[$option] = (int) $value;
                    }
                }
            }
        } catch (FilesystemException $e) {
            // use default
        }

        yield new CoroutineResult($result);
    }

    private function loadWindowsRegistryConfig()
    {
        $result = $this->defaultServerConfig;
        $keys = [
            'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\NameServer',
            'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DhcpNameServer',
        ];

        $reader = new WindowsRegistry;
        $server = '';

        while ($server === '' && ($key = array_shift($keys))) {
            try {
                $server = (yield $reader->read($key));
            } catch (KeyNotFoundException $e) { }
        }

        if ($server === '') {
            $subKeys = (yield $reader->listKeys('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'));

            while ($server === '' && ($key = array_shift($subKeys))) {
                try {
                    $server = (yield $reader->read($key . '\NameServer'));
                } catch (KeyNotFoundException $e) { }
            }
        }

        if ($server === '') {
            throw new ResolutionException('Could not find a nameserver in the Windows Registry.');
        }

        // Microsoft documents space as delimiter, AppVeyor uses comma.
        $result['nameservers'] = array_map(function ($ns) {
            return trim($ns) . ':53';
        }, explode(' ', strtr($server, ',', ' ')));

        yield new CoroutineResult($result);
    }

    private function loadSystemServerConfig($path = null) {
        if ($this->systemServerConfigLoadPromise !== null) {
            return $this->systemServerConfigLoadPromise;
        }

        $generator = self::$isWindows && $path == null
            ? $this->loadWindowsRegistryConfig()
            : $this->loadResolvConf($path ?: self::RESOLV_CONF_PATH);

        return $this->systemServerConfigLoadPromise = \Amp\resolve($generator)->when(function () {
            $this->systemServerConfigLoadPromise = null;
        });
    }

    private function loadHostsFile($path = null)
    {
        if ($this->hostsFileLoadPromise !== null) {
            return $this->hostsFileLoadPromise;
        }

        if (empty($path)) {
            $path = self::$isWindows
                ? self::HOSTS_FILE_PATH_WIN
                : self::HOSTS_FILE_PATH;
        }

        return $this->hostsFileLoadPromise = \Amp\resolve($this->doLoadHostsFile($path))->when(function () {
            $this->hostsFileLoadPromise = null;
        });
    }

    private function doLoadHostsFile($path)
    {
        $data = [];

        try {
            $contents = (yield \Amp\File\get($path));
        } catch (\Exception $e) {
            yield new CoroutineResult($data);
            return;
        }

        foreach (\array_filter(\array_map('trim', \explode("\n", $contents))) as $line) {
            if ($line[0] === '#') {
                continue;
            }

            $parts = \preg_split('/\s+/', $line);

            if (!($ip = @\inet_pton($parts[0]))) {
                continue;
            } else if (isset($ip[4])) {
                $key = Record::AAAA;
            } else {
                $key = Record::A;
            }

            for ($i = 1, $l = \count($parts); $i < $l; $i++) {
                if (\Amp\Dns\isValidHostName($parts[$i])) {
                    $data[$key][strtolower($parts[$i])] = $parts[0];
                }
            }
        }

        // Windows does not include localhost in its host file. Fetch it from the system instead
        if (!isset($data[Record::A]['localhost']) && !isset($data[Record::AAAA]['localhost'])) {
            // PHP currently provides no way to **resolve** IPv6 hostnames (not even with fallback)
            $local = gethostbyname('localhost');

            if ($local !== 'localhost') {
                $data[Record::A]['localhost'] = $local;
            } else {
                $data[Record::AAAA]['localhost'] = '::1';
            }
        }

        yield new CoroutineResult($data);
    }

    private function parseCustomServerUri($uri)
    {
        if (!\is_string($uri)) {
            throw new ResolutionException(
                'Invalid server address ($uri must be a string IP address, ' . gettype($uri) . " given)"
            );
        }

        $parts = explode('://', $uri);

        if (isset($parts[1])) {
            $protocol = $parts[0];
            $addr = $parts[1];
        } else {
            $protocol = null;
            $addr = $parts[0];
        }

        if (($colonPos = strrpos($addr, ':')) !== false) {
            $host = \substr($addr, 0, $colonPos);
            $port = (int)\substr($addr, $colonPos + 1);
        } else {
            $host = $addr;
            $port = 53;
        }

        if (!$inAddr = @\inet_pton(\trim($host))) {
            throw new ResolutionException('Invalid server $uri; string IP address required');
        }

        $protocols = Server::PROTOCOL_ANY;

        if ($protocol === 'udp') {
            $protocols &= ~Server::PROTOCOL_TCP;
        } else if ($protocol === 'tcp') {
            $protocols &= ~Server::PROTOCOL_TCP;
        }

        return [$this->getServer("{$host}:{$port}"), $protocols];
    }

    private function loadExistingServer($uri) {
        if (empty($this->serverUriMap[$uri])) {
            return null;
        }

        $server = $this->serverUriMap[$uri];

        if (\is_resource($server->socket)) {
            unset($this->serverIdTimeoutMap[$server->id]);
            \Amp\enable($server->watcherId);
            return $server;
        }

        $this->unloadServer($server->id);
        return null;
    }

    private function loadNewServer($uri) {
        if (!$socket = @\stream_socket_client($uri, $errno, $errstr, 0, STREAM_CLIENT_ASYNC_CONNECT)) {
            throw new ResolutionException(sprintf(
                "Connection to %s failed: [Error #%d] %s",
                $uri,
                $errno,
                $errstr
            ));
        }

        \stream_set_blocking($socket, false);
        $id = (int) $socket;
        $server = new \StdClass;
        $server->id = $id;
        $server->uri = $uri;
        $server->socket = $socket;
        $server->buffer = "";
        $server->length = INF;
        $server->pendingRequests = [];
        $server->watcherId = \Amp\onReadable($socket, $this->makePrivateCallable("onReadable"), [
            "enable" => true,
            "keep_alive" => true,
        ]);
        $this->serverIdMap[$id] = $server;
        $this->serverUriMap[$uri] = $server;

        if (substr($uri, 0, 6) == "tcp://") {
            $promisor = new Deferred;
            $server->connect = $promisor->promise();
            $watcher = \Amp\onWritable($server->socket, static function($watcher) use ($server, $promisor, &$timer) {
                \Amp\cancel($watcher);
                \Amp\cancel($timer);
                unset($server->connect);
                $promisor->succeed();
            });
            $timer = \Amp\once(function() use ($id, $promisor, $watcher, $uri) {
                \Amp\cancel($watcher);
                $this->unloadServer($id);
                $promisor->fail(new TimeoutException("Name resolution timed out, could not connect to server at $uri"));
            }, 5000);
        }

        return $server;
    }

    private function unloadServer($serverId, $error = null) {
        // Might already have been unloaded (especially if multiple requests happen)
        if (!isset($this->serverIdMap[$serverId])) {
            return;
        }

        $server = $this->serverIdMap[$serverId];
        \Amp\cancel($server->watcherId);
        unset(
            $this->serverIdMap[$serverId],
            $this->serverUriMap[$server->uri]
        );
        if (\is_resource($server->socket)) {
            @\fclose($server->socket);
        }
        if ($error && $server->pendingRequests) {
            foreach (array_keys($server->pendingRequests) as $requestId) {
                list($promisor) = $this->pendingRequests[$requestId];
                $promisor->fail($error);
            }
        }
    }

    private function onReadable($watcherId, $socket) {
        $serverId = (int) $socket;
        $packet = @\fread($socket, 512);
        if ($packet != "") {
            $server = $this->serverIdMap[$serverId];
            if (\substr($server->uri, 0, 6) == "tcp://") {
                if ($server->length == INF) {
                    $server->length = unpack("n", $packet)[1];
                    $packet = substr($packet, 2);
                }
                $server->buffer .= $packet;
                while ($server->length <= \strlen($server->buffer)) {
                    $this->decodeResponsePacket($serverId, substr($server->buffer, 0, $server->length));
                    $server->buffer = substr($server->buffer, $server->length);
                    if (\strlen($server->buffer) >= 2 + $server->length) {
                        $server->length = unpack("n", $server->buffer)[1];
                        $server->buffer = substr($server->buffer, 2);
                    } else {
                        $server->length = INF;
                    }
                }
            } else {
                $this->decodeResponsePacket($serverId, $packet);
            }
        } else {
            $this->unloadServer($serverId, new ResolutionException(
                "Server connection failed"
            ));
        }
    }

    private function decodeResponsePacket($serverId, $packet) {
        try {
            $response = $this->decoder->decode($packet);
            $requestId = $response->getID();
            $responseCode = $response->getResponseCode();
            $responseType = $response->getType();

            if ($responseCode !== 0) {
                $this->finalizeResult($serverId, $requestId, new ResolutionException(
                    "Server returned error code: {$responseCode}"
                ));
            } elseif ($responseType !== MessageTypes::RESPONSE) {
                $this->unloadServer($serverId, new ResolutionException(
                    "Invalid server reply; expected RESPONSE but received QUERY"
                ));
            } else {
                $this->processDecodedResponse($serverId, $requestId, $response);
            }
        } catch (\Exception $e) {
            $this->unloadServer($serverId, new ResolutionException(
                "Response decode error", 0, $e
            ));
        }
    }

    private function processDecodedResponse($serverId, $requestId, $response) {
        list($promisor, $name, $type, $uri) = $this->pendingRequests[$requestId];

        // Retry via tcp if message has been truncated
        if ($response->isTruncated()) {
            if (\substr($uri, 0, 6) != "tcp://") {
                $uri = \preg_replace("#[a-z.]+://#", "tcp://", $uri);
                $promisor->succeed($this->doRequest($uri, $name, $type));
            } else {
                $this->finalizeResult($serverId, $requestId, new ResolutionException(
                    "Server returned truncated response"
                ));
            }
            return;
        }

        $answers = $response->getAnswerRecords();
        foreach ($answers as $record) {
            $result[$record->getType()][] = [(string) $record->getData(), $record->getType(), $record->getTTL()];
        }
        if (empty($result)) {
            $this->cache->set("$name#$type", [], 300); // "it MUST NOT cache it for longer than five (5) minutes" per RFC 2308 section 7.1
            $this->finalizeResult($serverId, $requestId, new NoRecordException(
                "No records returned for {$name}"
            ));
        } else {
            $this->finalizeResult($serverId, $requestId, $error = null, $result);
        }
    }

    private function finalizeResult($serverId, $requestId, $error = null, $result = null) {
        if (empty($this->pendingRequests[$requestId])) {
            return;
        }

        list($promisor, $name) = $this->pendingRequests[$requestId];
        $server = $this->serverIdMap[$serverId];
        unset(
            $this->pendingRequests[$requestId],
            $server->pendingRequests[$requestId]
        );
        if (empty($server->pendingRequests)) {
            $this->serverIdTimeoutMap[$server->id] = $this->now + IDLE_TIMEOUT;
            \Amp\disable($server->watcherId);
            \Amp\enable($this->serverTimeoutWatcher);
        }
        if ($error) {
            $promisor->fail($error);
        } else {
            foreach ($result as $type => $records) {
                $minttl = INF;
                foreach ($records as list( , $ttl)) {
                    if ($ttl && $minttl > $ttl) {
                        $minttl = $ttl;
                    }
                }
                $this->cache->set("$name#$type", $records, $minttl);
            }
            $promisor->succeed($result);
        }
    }

    private function makePrivateCallable($method) {
        return (new \ReflectionClass($this))->getMethod($method)->getClosure($this);
    }
}
