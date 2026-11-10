<?php

declare(strict_types=1);

/**
 * Lokales Tuya-Protokoll 3.3 / 3.4 / 3.5
 * Eine Verbindung pro Vorgang (Abfrage oder Schaltbefehl).
 */
class TuyaLocalClient
{
    private const PORT = 6668;
    private $sock;
    private string $key;
    private string $sk = '';
    private int $seq = 0;

    public function __construct(private string $host, private string $id, string $localKey, private string $version)
    {
        $this->key = $localKey;
    }

    public static function detect(string $host, string $id, string $key): string
    {
        foreach (['3.5', '3.4', '3.3'] as $v) {
            try {
                $c = new self($host, $id, $key, $v);
                $c->query();
                return $v;
            } catch (Throwable $e) {
            }
        }
        throw new Exception('Protokollversion nicht erkannt (Key, IP oder Gerät prüfen)');
    }

    public function query(): array
    {
        $this->open();
        try {
            $json = json_encode(['gwId' => $this->id, 'devId' => $this->id, 'uid' => $this->id, 't' => (string) time(), 'dps' => new stdClass()]);
            if ($this->version === '3.3') {
                $this->send(10, $this->ecb($json, $this->key));
            } else {
                $this->send(16, $json);
            }
            foreach ($this->read(3.0, $this->version === '3.3' ? 10 : 16) as $m) {
                $j = json_decode($m['data'], true);
                if (isset($j['dps'])) {
                    return $j['dps'];
                }
            }
            throw new Exception('Keine Statusantwort');
        } finally {
            $this->close();
        }
    }

    public function set(array $dps): array
    {
        $this->open();
        try {
            if ($this->version === '3.3') {
                $json = json_encode(['devId' => $this->id, 'uid' => $this->id, 't' => (string) time(), 'dps' => $dps]);
                $this->send(7, '3.3' . str_repeat("\0", 12) . $this->ecb($json, $this->key));
            } else {
                $json = json_encode(['protocol' => 5, 't' => time(), 'data' => ['dps' => $dps]]);
                $this->send(13, $this->version . str_repeat("\0", 12) . $json);
            }
            $res = [];
            foreach ($this->read(2.0, 8) as $m) {
                $j = json_decode($m['data'], true);
                if (isset($j['data']['dps'])) {
                    $res = $j['data']['dps'] + $res;
                } elseif (isset($j['dps'])) {
                    $res = $j['dps'] + $res;
                }
            }
            return $res ?: $dps;
        } finally {
            $this->close();
        }
    }

    // ---------- Verbindung ----------

    private function open(): void
    {
        $this->sock = @fsockopen($this->host, self::PORT, $en, $es, 3);
        if (!$this->sock) {
            throw new Exception("nicht erreichbar ($es)");
        }
        $this->seq = 0;
        $this->sk = $this->key;
        if ($this->version === '3.4' || $this->version === '3.5') {
            $ln = random_bytes(16);
            $this->send(3, $ln);
            $r = $this->read(3.0, 4);
            $m = end($r);
            if (!$m || $m['cmd'] != 4) {
                $this->close();
                throw new Exception('kein Schlüsselaustausch');
            }
            $rn = substr($m['data'], 0, 16);
            if (!hash_equals(hash_hmac('sha256', $ln, $this->key, true), substr($m['data'], 16, 32))) {
                $this->close();
                throw new Exception('HMAC ungültig (Local Key falsch?)');
            }
            $this->send(5, hash_hmac('sha256', $rn, $this->key, true));
            if ($this->version === '3.5') {
                $tag = '';
                $this->sk = substr(openssl_encrypt($ln ^ $rn, 'aes-128-gcm', $this->key, OPENSSL_RAW_DATA, substr($ln, 0, 12), $tag), 0, 16);
            } else {
                $this->sk = substr(openssl_encrypt($ln ^ $rn, 'aes-128-ecb', $this->key, OPENSSL_RAW_DATA), 0, 16);
            }
        }
    }

    private function close(): void
    {
        if ($this->sock) {
            @fclose($this->sock);
        }
        $this->sock = null;
    }

    private function send(int $cmd, string $payload): void
    {
        $this->seq++;
        if ($this->version === '3.5') {
            $iv = random_bytes(12);
            $hdr = pack('nNNN', 0, $this->seq, $cmd, 12 + strlen($payload) + 16);
            $tag = '';
            $ct = openssl_encrypt($payload, 'aes-128-gcm', $this->sk, OPENSSL_RAW_DATA, $iv, $tag, $hdr, 16);
            $pkt = pack('N', 0x6699) . $hdr . $iv . $ct . $tag . pack('N', 0x9966);
        } elseif ($this->version === '3.4') {
            $pl = $this->ecb($payload, $this->sk);
            $body = pack('NNNN', 0x55AA, $this->seq, $cmd, strlen($pl) + 36) . $pl;
            $pkt = $body . hash_hmac('sha256', $body, $this->sk, true) . pack('N', 0xAA55);
        } else {
            $body = pack('NNNN', 0x55AA, $this->seq, $cmd, strlen($payload) + 8) . $payload;
            $pkt = $body . pack('N', crc32($body)) . pack('N', 0xAA55);
        }
        fwrite($this->sock, $pkt);
    }

    private function read(float $timeout, ?int $want): array
    {
        $buf = '';
        $out = [];
        $end = microtime(true) + $timeout;
        stream_set_timeout($this->sock, 0, 300000);
        while (microtime(true) < $end) {
            $c = fread($this->sock, 4096);
            if ($c !== false && $c !== '') {
                $buf .= $c;
            }
            while (($m = $this->unpack($buf)) !== null) {
                $out[] = $m;
                if ($want !== null && $m['cmd'] == $want) {
                    return $out;
                }
            }
            if (feof($this->sock)) {
                break;
            }
        }
        return $out;
    }

    private function unpack(string &$buf): ?array
    {
        if (strlen($buf) < 16) {
            return null;
        }
        $pre = unpack('N', substr($buf, 0, 4))[1];
        if ($pre === 0x6699) {
            if (strlen($buf) < 18) {
                return null;
            }
            $h = unpack('nx/Nseq/Ncmd/Nlen', substr($buf, 4, 14));
            if (strlen($buf) < 22 + $h['len']) {
                return null;
            }
            $hdr = substr($buf, 4, 14);
            $body = substr($buf, 18, $h['len']);
            $buf = substr($buf, 22 + $h['len']);
            $pt = openssl_decrypt(substr($body, 12, -16), 'aes-128-gcm', $this->sk, OPENSSL_RAW_DATA, substr($body, 0, 12), substr($body, -16), $hdr);
            if ($pt === false) {
                throw new Exception('Entschlüsselung fehlgeschlagen');
            }
            return ['cmd' => $h['cmd'], 'data' => $this->strip($pt)];
        }
        if ($pre !== 0x55AA) {
            throw new Exception('ungültiger Header');
        }
        $h = unpack('Nseq/Ncmd/Nlen', substr($buf, 4, 12));
        if (strlen($buf) < 16 + $h['len']) {
            return null;
        }
        $data = substr($buf, 16, $h['len']);
        $buf = substr($buf, 16 + $h['len']);
        $p = substr($data, 0, $this->version === '3.4' ? -36 : -8);
        if (strlen($p) >= 4 && !(unpack('N', substr($p, 0, 4))[1] & 0xFFFFFF00)) {
            $p = substr($p, 4);
        }
        if ($p === '') {
            return ['cmd' => $h['cmd'], 'data' => ''];
        }
        if (substr($p, 0, 3) === '3.3') {
            $p = substr($p, 15);
        }
        if (substr($p, 0, 1) === '{') {
            return ['cmd' => $h['cmd'], 'data' => $p];
        }
        $pt = openssl_decrypt($p, 'aes-128-ecb', $this->sk, OPENSSL_RAW_DATA);
        if ($pt === false) {
            throw new Exception('Entschlüsselung fehlgeschlagen');
        }
        return ['cmd' => $h['cmd'], 'data' => $this->strip($pt)];
    }

    private function strip(string $pt): string
    {
        if (strlen($pt) >= 4 && !(unpack('N', substr($pt, 0, 4))[1] & 0xFFFFFF00) && substr($pt, 4, 1) !== '') {
            $pt = substr($pt, 4);
        }
        if (preg_match('/^3\.\d/', $pt)) {
            $pt = substr($pt, 15);
        }
        return $pt;
    }

    private function ecb(string $d, string $k): string
    {
        return openssl_encrypt($d, 'aes-128-ecb', $k, OPENSSL_RAW_DATA);
    }
}