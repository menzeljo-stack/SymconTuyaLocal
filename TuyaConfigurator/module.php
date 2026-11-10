<?php

declare(strict_types=1);

/**
 * Tuya Konfigurator: liest einmalig Geräte, Local Keys und MAC-Adressen
 * aus dem Tuya-Cloud-Projekt und legt lokale Tuya-Geräte-Instanzen an.
 * Die Steuerung selbst läuft danach komplett lokal.
 */
class TuyaConfigurator extends IPSModule
{
    private const DEVICE_GUID = '{4419CC3C-AB82-4626-A4B2-0DF1A34B8A30}';
    private const ENDPOINTS = [
        'eu'  => 'https://openapi.tuyaeu.com',
        'weu' => 'https://openapi-weaz.tuyaeu.com',
        'us'  => 'https://openapi.tuyaus.com',
        'cn'  => 'https://openapi.tuyacn.com',
        'in'  => 'https://openapi.tuyain.com',
    ];

    public function Create()
    {
        parent::Create();
        $this->RegisterPropertyString('AccessID', '');
        $this->RegisterPropertyString('AccessSecret', '');
        $this->RegisterPropertyString('Region', 'eu');
        $this->RegisterPropertyInteger('ImportCategory', 0);
    }

    public function ApplyChanges()
    {
        parent::ApplyChanges();
        $this->SetStatus($this->ReadPropertyString('AccessID') !== '' && $this->ReadPropertyString('AccessSecret') !== '' ? 102 : 104);
    }

    public function GetConfigurationForm()
    {
        $values = [];
        $error = '';
        if ($this->ReadPropertyString('AccessID') !== '' && $this->ReadPropertyString('AccessSecret') !== '') {
            try {
                $values = $this->buildList();
            } catch (Throwable $e) {
                $error = $e->getMessage();
            }
        }
        $form = json_decode(file_get_contents(__DIR__ . '/form.json'), true);
        foreach ($form['actions'] as &$a) {
            if (($a['name'] ?? '') === 'Devices') {
                $a['values'] = $values;
            }
        }
        unset($a);
        if ($error !== '') {
            array_unshift($form['actions'], ['type' => 'Label', 'caption' => '⚠️ Tuya-Cloud: ' . $error]);
        }
        return json_encode($form);
    }

    /** Liste für den Konfigurator */
    private function buildList(): array
    {
        $devices = $this->cloudDevices();
        $macs = [];
        $ids = array_column($devices, 'id');
        foreach (array_chunk($ids, 20) as $chunk) {
            foreach ($this->api('GET', '/v1.0/devices/factory-infos', ['device_ids' => implode(',', $chunk)]) as $f) {
                if (!empty($f['mac'])) {
                    $macs[$f['id']] = $f['mac'];
                }
            }
        }
        $arp = $this->arpTable();

        // vorhandene Instanzen
        $existing = [];
        foreach (IPS_GetInstanceListByModuleID(self::DEVICE_GUID) as $i) {
            $existing[IPS_GetProperty($i, 'DeviceID')] = $i;
        }

        $cat = $this->ReadPropertyInteger('ImportCategory');
        $path = [];
        while ($cat > 0 && IPS_ObjectExists($cat)) {
            array_unshift($path, IPS_GetName($cat));
            $cat = IPS_GetParent($cat);
        }

        $values = [];
        foreach ($devices as $d) {
            $mac = $macs[$d['id']] ?? '';
            $ip = $arp[strtolower(preg_replace('/[^0-9a-f]/i', '', $mac))] ?? '';
            $row = [
                'name'       => $d['name'] ?? $d['id'],
                'product'    => $d['product_name'] ?? '',
                'category'   => $d['category'] ?? '',
                'id'         => $d['id'],
                'ip'         => $ip ?: '–',
                'online'     => ($d['online'] ?? false) ? 'ja' : 'nein',
                'instanceID' => $existing[$d['id']] ?? 0,
                'create'     => [
                    'moduleID'      => self::DEVICE_GUID,
                    'configuration' => [
                        'DeviceID' => $d['id'],
                        'LocalKey' => $d['local_key'] ?? '',
                        'MAC'      => $mac,
                        'Host'     => '',
                    ],
                    'location'      => $path,
                ],
            ];
            unset($existing[$d['id']]);
            $values[] = $row;
        }
        // Instanzen, die nicht (mehr) in der Cloud sind
        foreach ($existing as $did => $inst) {
            $values[] = ['name' => IPS_GetName($inst), 'product' => '', 'category' => '', 'id' => $did, 'ip' => IPS_GetProperty($inst, 'Host'), 'online' => '?', 'instanceID' => $inst];
        }
        return $values;
    }

    /** Aktualisiert Local Keys aller vorhandenen Instanzen (z. B. nach Neu-Anlernen) */
    public function UpdateKeys(): string
    {
        $n = 0;
        $keys = array_column($this->cloudDevices(), 'local_key', 'id');
        foreach (IPS_GetInstanceListByModuleID(self::DEVICE_GUID) as $i) {
            $id = IPS_GetProperty($i, 'DeviceID');
            if (isset($keys[$id]) && $keys[$id] !== IPS_GetProperty($i, 'LocalKey')) {
                IPS_SetProperty($i, 'LocalKey', $keys[$id]);
                IPS_ApplyChanges($i);
                $n++;
            }
        }
        return $n . ' Local Key(s) aktualisiert';
    }

    private function cloudDevices(): array
    {
        $all = [];
        $last = '';
        do {
            $q = ['size' => 100];
            if ($last !== '') {
                $q['last_row_key'] = $last;
            }
            $r = $this->api('GET', '/v1.0/iot-01/associated-users/devices', $q);
            $all = array_merge($all, $r['devices'] ?? []);
            $last = ($r['has_more'] ?? false) ? ($r['last_row_key'] ?? '') : '';
        } while ($last !== '');
        return $all;
    }

    private function arpTable(): array
    {
        $map = [];
        foreach (explode("\n", (string) @shell_exec('arp -a')) as $l) {
            if (preg_match('/(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:[-:][0-9a-f]{2}){5})/i', $l, $m)) {
                $map[strtolower(preg_replace('/[^0-9a-f]/i', '', $m[2]))] = $m[1];
            }
        }
        return $map;
    }

    // ---------- Tuya OpenAPI ----------

    private function token(): string
    {
        $cache = json_decode($this->GetBuffer('Token'), true);
        if (is_array($cache) && ($cache['exp'] ?? 0) > time() + 60) {
            return $cache['token'];
        }
        $r = $this->request('GET', '/v1.0/token', ['grant_type' => 1], '');
        $this->SetBuffer('Token', json_encode(['token' => $r['access_token'], 'exp' => time() + (int) $r['expire_time']]));
        return $r['access_token'];
    }

    private function api(string $method, string $path, array $query = [])
    {
        return $this->request($method, $path, $query, $this->token());
    }

    private function request(string $method, string $path, array $query, string $token)
    {
        ksort($query);
        $qs = http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        $url = $path . ($qs !== '' ? '?' . urldecode($qs) : '');
        $id = $this->ReadPropertyString('AccessID');
        $t = (string) round(microtime(true) * 1000);
        $stringToSign = $method . "\n" . hash('sha256', '') . "\n\n" . $url;
        $sign = strtoupper(hash_hmac('sha256', $id . $token . $t . $stringToSign, $this->ReadPropertyString('AccessSecret')));
        $headers = ['client_id: ' . $id, 'sign: ' . $sign, 't: ' . $t, 'sign_method: HMAC-SHA256'];
        if ($token !== '') {
            $headers[] = 'access_token: ' . $token;
        }
        $base = self::ENDPOINTS[$this->ReadPropertyString('Region')] ?? self::ENDPOINTS['eu'];
        $ch = curl_init($base . $path . ($qs !== '' ? '?' . $qs : ''));
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $headers, CURLOPT_TIMEOUT => 10, CURLOPT_CUSTOMREQUEST => $method]);
        $res = curl_exec($ch);
        $err = curl_error($ch);
        curl_close($ch);
        if ($res === false) {
            throw new Exception('Verbindung fehlgeschlagen: ' . $err);
        }
        $j = json_decode($res, true);
        if (!($j['success'] ?? false)) {
            throw new Exception(($j['msg'] ?? 'unbekannter Fehler') . ' (Code ' . ($j['code'] ?? '?') . ')');
        }
        return $j['result'];
    }
}