<?php

namespace Amp\Dns;

use Amp\Cache\ArrayCache;
use Amp\Cache\Cache;
use Amp\CoroutineResult;
use Amp\Deferred;
use Amp\Failure;
use Amp\File\FilesystemException;
use Amp\Success;
use Amp\WindowsRegistry\KeyNotFoundException;
use Amp\WindowsRegistry\WindowsRegistry;
use LibDNS\Decoder\DecoderFactory;
use LibDNS\Encoder\EncoderFactory;
use LibDNS\Messages\Message;
use LibDNS\Messages\MessageFactory;
use LibDNS\Records\QuestionFactory;
use LibDNS\Records\Resource as ResourceRecord;

class DefaultResolver implements Resolver
{
    const RESOLV_CONF_PATH = '/etc/resolv.conf';
    const HOSTS_FILE_PATH = '/etc/hosts';
    const HOSTS_FILE_PATH_WIN = 'C:\Windows\system32\drivers\etc\hosts';

    private static $isWindows;

    private $defaultServerConfig = [
        "nameservers" => [
            "8.8.8.8",
            "8.8.4.4",
        ],
        Option::REQUEST_TIMEOUT  => DEFAULT_REQUEST_TIMEOUT,
        Option::REQUEST_ATTEMPTS => DEFAULT_REQUEST_ATTEMPTS,
    ];

    private $messageFactory;
    private $questionFactory;
    private $cache;

    private $requestDispatcher;
    private $serverManager;

    private $systemServerConfig;
    private $systemServerConfigLoadPromise;

    private $hostsFileData;
    private $hostsFileLoadPromise;

    private $defaultServerList = [];
    private $pendingResolveLookups = [];

    public function __construct(Cache $cache = null)
    {
        self::$isWindows = \stripos(PHP_OS, "win") === 0;

        $this->messageFactory = new MessageFactory;
        $this->questionFactory = new QuestionFactory;
        $this->cache = isset($cache) ? $cache : new ArrayCache;

        $encoder = (new EncoderFactory)->create();
        $decoder = (new DecoderFactory)->create(null, true);

        $this->serverManager = new ServerManager($encoder, $decoder);
        $this->requestDispatcher = new RequestDispatcher($this->serverManager, $encoder, $decoder);
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

        $name = strtolower($name);
        $key = "{$name}#" . implode('/', $types);

        if (isset($this->pendingResolveLookups[$key])) {
            return $this->pendingResolveLookups[$key];
        }

        return $this->pendingResolveLookups[$key] = $this->flattenResults(\Amp\resolve($this->resolveName($name, $types, $options)), $types)
            ->when(function() use($key) {
                unset($this->pendingResolveLookups[$key]);
            });
    }

    /**
     * {@inheritdoc}
     * @todo generally everything
     */
    public function query($name, $type, array $options = [])
    {
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
            try {
                /** @var Server $server */
                $server = $serverInfo['server'];
                $protocols = $serverInfo['protocols'];

                /** @var Message[] $results */
                $results = (yield $this->requestDispatcher->sendQuestionsToServer($server, $protocols, $questions, $options));
            } catch (\Exception $e) {
                // if a request fails for one of the system default servers, move it to the end of the list
                if ($server->isSystemServer) {
                    unset($this->defaultServerList[$server->address]);
                    $this->defaultServerList[$server->address] = $serverInfo;
                }

                continue;
            }

            /** @var ResourceRecord $record */
            foreach ($results as $result) {
                foreach ($result->getAnswerRecords() as $record) {
                    $type = $record->getType();

                    if (!isset($types[$type])) {
                        continue; // todo: handle other record types properly
                    }

                    $records[$type][] = [(string)$record->getData(), $type, $record->getTTL()];
                }
            }

            yield new CoroutineResult($records);
            return;
        }
    }

    private function onSystemServerConfigLoaded($error, $result, Deferred $deferred)
    {
        if ($error) {
            $deferred->fail($error);
            return;
        }

        if (empty($result['nameservers'])) {
            $deferred->fail(new ResolutionException('No valid nameserver specified in system config'));
            return;
        }

        $this->systemServerConfig = $result;

        foreach ($result['nameservers'] as $host) {
            if (!$ipAddr = \inet_pton($host)) {
                continue;
            }

            if (!isset($ipAddr[4])) {
                $addressFamily = STREAM_PF_INET;
            } else if (!$this->requestDispatcher->haveIPv6Support()) {
                continue; // we were unable to bind an IPv6 socket so ignore IPv6 servers
            } else {
                $host = "[{$host}]";
                $addressFamily = STREAM_PF_INET6;
            }

            $address = "{$host}:53";
            $this->defaultServerList[$address] = [
                'server' => $this->serverManager->createOrRetrieveServer($address, $addressFamily, [
                    Server::OP_IS_SYSTEM_SERVER => true,
                    Option::REQUEST_TIMEOUT     => $result[Option::REQUEST_TIMEOUT],
                    Option::TCP_CONNECT_TIMEOUT => DEFAULT_TCP_CONNECT_TIMEOUT,
                    Option::TCP_IDLE_TIMEOUT    => DEFAULT_TCP_IDLE_TIMEOUT,
                ]),
                'protocols' => Server::PROTOCOL_ANY,
            ];
        }

        if (empty($this->defaultServerList)) {
            $deferred->fail(new ResolutionException('No valid nameserver specified in system config'));
            return;
        }

        $deferred->succeed($this->defaultServerList);
    }

    private function getServerListForRequest($options)
    {
        if (!empty($options['server'])) {
            try {
                return new Success([$this->parseCustomServerUri($options)]);
            } catch (\Exception $e) {
                return new Failure($e);
            }
        }

        if (isset($this->systemServerConfig)) {
            return new Success($this->defaultServerList);
        }

        $deferred = new Deferred;

        $this->loadSystemServerConfig()->when(function($error, $result) use($deferred) {
            $this->onSystemServerConfigLoaded($error, $result, $deferred);
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

    /**
     * @link http://man7.org/linux/man-pages/man5/resolv.conf.5.html
     * @param string $path
     * @return \Generator
     */
    private function loadResolvConf($path)
    {
        static $mappedOptions = [
            'timeout' => Option::REQUEST_TIMEOUT,
            'attempts' => Option::REQUEST_ATTEMPTS,
        ];

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

                    if ($ip !== false) {
                        $result["nameservers"][] = $line[1];
                    }
                } else if ($type === "options") {
                    $optline = preg_split('#\s+#', $value, 2);
                    if (\count($optline) !== 2) {
                        continue;
                    }

                    list($option, $value) = $optline;

                    if (isset($mappedOptions[$option])) {
                        $result[$mappedOptions[$option]] = (int)$value;
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
            return trim($ns);
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

    private function parseCustomServerUri($options)
    {
        $uri = $options['server'];

        if (!\is_string($uri)) {
            throw new ResolutionException(
                'Invalid server address ($uri must be a string IP address, ' . gettype($uri) . " given)"
            );
        }

        if (!empty($options['request_timeout'])) {
            $defaultRequestTimeout = (int)$options['request_timeout'];
        } else if (!empty($options['timeout'])) { // backwards compat
            $defaultRequestTimeout = (int)$options['timeout'];
        } else {
            $defaultRequestTimeout = $this->defaultServerConfig['request_timeout'];
        }

        $tcpConnectTimeout = !empty($options['tcp_connect_timeout'])
            ? (int)$options['tcp_connect_timeout']
            : DEFAULT_TCP_CONNECT_TIMEOUT;
        $tcpIdleTimeout = !empty($options['tcp_idle_timeout'])
            ? (int)$options['tcp_idle_timeout']
            : DEFAULT_TCP_IDLE_TIMEOUT;

        $parts = explode('://', $uri);

        if (isset($parts[1])) {
            $protocol = $parts[0];
            $addr = $parts[1];
        } else {
            $protocol = null;
            $addr = $parts[0];
        }

        if (($colonPos = \strrpos($addr, ':')) !== false) {
            $host = \trim(\substr($addr, 0, $colonPos), '[]');
            $port = (int)\substr($addr, $colonPos + 1);
        } else {
            $host = \trim($addr, '[]');
            $port = 53;
        }

        if (!$inAddr = @\inet_pton($host)) {
            throw new ResolutionException('Invalid server $uri; string IP address required');
        }

        if (isset($inAddr[4])) {
            if (!$this->requestDispatcher->haveIPv6Support()) {
                throw new ResolutionException('Binding local IPv6 socket failed, unable to use IPv6 server address');
            }

            $host = "[{$host}]";
            $addressFamily = STREAM_PF_INET6;
        } else {
            $addressFamily = STREAM_PF_INET;
        }

        $protocols = Server::PROTOCOL_ANY;

        if ($protocol === 'udp') {
            $protocols &= ~Server::PROTOCOL_TCP;
        } else if ($protocol === 'tcp') {
            $protocols &= ~Server::PROTOCOL_UDP;
        }

        return [
            'server' => $this->serverManager->createOrRetrieveServer("{$host}:{$port}", $addressFamily, [
                Server::OP_IS_SYSTEM_SERVER => false,
                Option::REQUEST_TIMEOUT     => $defaultRequestTimeout,
                Option::TCP_CONNECT_TIMEOUT => $tcpConnectTimeout,
                Option::TCP_IDLE_TIMEOUT    => $tcpIdleTimeout,
            ]),
            'protocols' => $protocols,
        ];
    }
}
