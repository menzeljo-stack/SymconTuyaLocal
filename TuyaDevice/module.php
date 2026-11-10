<?php

declare(strict_types=1);

require_once __DIR__ . '/../libs/TuyaLocalClient.php';

/**
 * Tuya-Gerät, lokal gesteuert (ohne Cloud).
 * Unterstützt Leuchten (Kategorie-unabhängig, DP 20–24) und Schalter/Steckdosen (DP 1–9 bool).
 */
class TuyaDevice extends IPSModule
{
    public function Create()
    {
        parent::Create();
        $this->RegisterPropertyString('DeviceID', '');
        $this->RegisterPropertyString('LocalKey', '');
        $this->RegisterPropertyString('Host', '');
        $this->RegisterPropertyString('MAC', '');
        $this->RegisterPropertyString('Version', 'auto');
        $this->RegisterPropertyInteger('Interval', 30);
        $this->RegisterPropertyInteger('CTMin', 2700);
        $this->RegisterPropertyInteger('CTMax', 6500);
        $this->RegisterPropertyBoolean('OfflineAsOff', true);

        $this->RegisterAttributeString('DetectedVersion', '');
        $this->RegisterAttributeString('KnownDPs', '[]');

        $this->RegisterTimer('Poll', 0, 'TUYA_Update($_IPS["TARGET"]);');
    }

    public function ApplyChanges()
    {
        parent::ApplyChanges();

        if (!IPS_VariableProfileExists('Tuya.ColorTemp')) {
            IPS_CreateVariableProfile('Tuya.ColorTemp', VARIABLETYPE_INTEGER);
            IPS_SetVariableProfileText('Tuya.ColorTemp', '', ' K');
            IPS_SetVariableProfileIcon('Tuya.ColorTemp', 'Bulb');
        }
        IPS_SetVariableProfileValues('Tuya.ColorTemp', $this->ReadPropertyInteger('CTMin'), $this->ReadPropertyInteger('CTMax'), 100);

        $this->WriteAttributeString('DetectedVersion', '');
        $ok = $this->ReadPropertyString('DeviceID') !== '' && strlen($this->ReadPropertyString('LocalKey')) === 16;
        if (!$ok) {
            $this->SetStatus(201);
            $this->SetTimerInterval('Poll', 0);
            return;
        }
        $this->SetSummary($this->host());
        $this->SetTimerInterval('Poll', max(5, $this->ReadPropertyInteger('Interval')) * 1000);
        if (IPS_GetKernelRunlevel() === KR_READY) {
            $this->Update();
        }
    }

    public function GetConfigurationForm()
    {
        $form = json_decode(file_get_contents(__DIR__ . '/form.json'), true);
        $form['actions'][] = ['type' => 'Label', 'caption' => 'Protokoll: ' . ($this->ReadAttributeString('DetectedVersion') ?: '–') . '   |   Datenpunkte: ' . $this->ReadAttributeString('KnownDPs')];
        return json_encode($form);
    }

    /** Status vom Gerät holen und Variablen aktualisieren */
    public function Update(): bool
    {
        try {
            $dps = $this->client()->query();
            $this->apply($dps);
            $this->SetStatus(102);
            return true;
        } catch (Throwable $e) {
            $this->offline($e->getMessage());
            return false;
        }
    }

    /** Rohe Datenpunkte setzen, z. B. TUYA_SetDPs(12345, ['20' => true]); */
    public function SetDPs(array $dps): bool
    {
        try {
            $res = $this->client()->set($dps);
            $this->apply($res + $dps);
            $this->SetStatus(102);
            return true;
        } catch (Throwable $e) {
            $this->offline($e->getMessage());
            return false;
        }
    }

    public function RequestAction($Ident, $Value)
    {
        $min = $this->ReadPropertyInteger('CTMin');
        $max = $this->ReadPropertyInteger('CTMax');
        switch ($Ident) {
            case 'Status':
                $dps = ['20' => (bool) $Value];
                break;
            case 'Helligkeit':
                $dps = $Value <= 0 ? ['20' => false] : ['20' => true, '21' => 'white', '22' => max(10, min(1000, (int) $Value * 10))];
                break;
            case 'Farbtemperatur':
                $dps = ['21' => 'white', '23' => (int) round(($Value - $min) / max(1, $max - $min) * 1000)];
                break;
            case 'Farbe':
                $dps = ['20' => true, '21' => 'colour', '24' => $this->rgbToTuya((int) $Value)];
                break;
            case 'Update':
                $this->Update();
                return;
            default:
                if (preg_match('/^Switch(\d+)$/', $Ident, $m)) {
                    $dps = [$m[1] => (bool) $Value];
                    break;
                }
                throw new Exception('Unbekannter Ident ' . $Ident);
        }
        if (!$this->SetDPs($dps)) {
            throw new Exception('Tuya-Gerät nicht erreichbar');
        }
        if ($Ident === 'Helligkeit' && $Value > 0) {
            $this->SetValue('Helligkeit', (int) $Value);
        }
    }

    // ---------- intern ----------

    private function client(): TuyaLocalClient
    {
        $id = $this->ReadPropertyString('DeviceID');
        $key = $this->ReadPropertyString('LocalKey');
        $host = $this->host();
        if ($host === '') {
            throw new Exception('IP-Adresse unbekannt');
        }
        $v = $this->ReadPropertyString('Version');
        if ($v === 'auto') {
            $v = $this->ReadAttributeString('DetectedVersion');
            if ($v === '') {
                $v = TuyaLocalClient::detect($host, $id, $key);
                $this->WriteAttributeString('DetectedVersion', $v);
            }
        }
        return new TuyaLocalClient($host, $id, $key, $v);
    }

    /** IP aus Eigenschaft, sonst per MAC aus der ARP-Tabelle */
    private function host(): string
    {
        $h = trim($this->ReadPropertyString('Host'));
        if ($h !== '') {
            return $h;
        }
        $mac = strtolower(preg_replace('/[^0-9a-f]/i', '', $this->ReadPropertyString('MAC')));
        if (strlen($mac) !== 12) {
            return '';
        }
        $arp = (string) @shell_exec('arp -a');
        foreach (explode("\n", $arp) as $l) {
            if (preg_match('/(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}[-:](?:[0-9a-f]{2}[-:]){4}[0-9a-f]{2})/i', $l, $m)
                && strtolower(preg_replace('/[^0-9a-f]/i', '', $m[2])) === $mac) {
                return $m[1];
            }
        }
        return '';
    }

    private function apply(array $dps): void
    {
        $known = json_decode($this->ReadAttributeString('KnownDPs'), true) ?: [];
        $new = array_values(array_unique(array_merge($known, array_map('strval', array_keys($dps)))));
        sort($new);
        if ($new !== $known) {
            $this->WriteAttributeString('KnownDPs', json_encode($new));
        }
        $min = $this->ReadPropertyInteger('CTMin');
        $max = $this->ReadPropertyInteger('CTMax');
        $isLight = in_array('20', $new, true);

        if ($isLight) {
            $this->MaintainVariable('Status', 'Status', VARIABLETYPE_BOOLEAN, '~Switch', 1, true);
            $this->EnableAction('Status');
            if (in_array('22', $new, true)) {
                $this->MaintainVariable('Helligkeit', 'Helligkeit', VARIABLETYPE_INTEGER, '~Intensity.100', 2, true);
                $this->EnableAction('Helligkeit');
            }
            if (in_array('23', $new, true)) {
                $this->MaintainVariable('Farbtemperatur', 'Farbtemperatur', VARIABLETYPE_INTEGER, 'Tuya.ColorTemp', 3, true);
                $this->EnableAction('Farbtemperatur');
            }
            if (in_array('24', $new, true)) {
                $this->MaintainVariable('Farbe', 'Farbe', VARIABLETYPE_INTEGER, '~HexColor', 4, true);
                $this->EnableAction('Farbe');
            }
            if (isset($dps['20'])) {
                $this->setIfChanged('Status', (bool) $dps['20']);
            }
            if (isset($dps['22']) && @$this->GetIDForIdent('Helligkeit')) {
                $this->setIfChanged('Helligkeit', (int) round($dps['22'] / 10));
            }
            if (isset($dps['23']) && @$this->GetIDForIdent('Farbtemperatur')) {
                $this->setIfChanged('Farbtemperatur', (int) (round(($min + $dps['23'] / 1000 * ($max - $min)) / 100) * 100));
            }
            if (isset($dps['24']) && @$this->GetIDForIdent('Farbe') && is_string($dps['24']) && strlen($dps['24']) === 12) {
                $this->setIfChanged('Farbe', $this->tuyaToRgb($dps['24']));
            }
            return;
        }

        // Schalter / Steckdosen: boolesche DPs 1–9
        foreach ($dps as $dp => $val) {
            if ((int) $dp >= 1 && (int) $dp <= 9 && is_bool($val)) {
                $ident = 'Switch' . $dp;
                $this->MaintainVariable($ident, count(array_filter($new, fn ($d) => (int) $d >= 1 && (int) $d <= 9)) > 1 ? 'Schalter ' . $dp : 'Status', VARIABLETYPE_BOOLEAN, '~Switch', (int) $dp, true);
                $this->EnableAction($ident);
                $this->setIfChanged($ident, $val);
            }
        }
    }

    private function offline(string $msg): void
    {
        $this->SendDebug('Fehler', $msg, 0);
        if (preg_match('/HMAC|Entschlüsselung|Protokollversion/', $msg)) {
            $this->WriteAttributeString('DetectedVersion', '');
        }
        if ($this->ReadPropertyBoolean('OfflineAsOff')) {
            foreach (['Status', 'Switch1'] as $i) {
                if (@$this->GetIDForIdent($i)) {
                    $this->setIfChanged($i, false);
                }
            }
        }
        if ($this->GetStatus() !== 200) {
            $this->LogMessage('nicht erreichbar: ' . $msg, KL_WARNING);
        }
        $this->SetStatus(200);
    }

    private function setIfChanged(string $ident, $val): void
    {
        if ($this->GetValue($ident) !== $val) {
            $this->SetValue($ident, $val);
        }
    }

    private function rgbToTuya(int $rgb): string
    {
        $r = (($rgb >> 16) & 255) / 255;
        $g = (($rgb >> 8) & 255) / 255;
        $b = ($rgb & 255) / 255;
        $mx = max($r, $g, $b);
        $mn = min($r, $g, $b);
        $d = $mx - $mn;
        $h = 0;
        if ($d > 0) {
            if ($mx == $r) {
                $h = 60 * fmod((($g - $b) / $d), 6);
            } elseif ($mx == $g) {
                $h = 60 * ((($b - $r) / $d) + 2);
            } else {
                $h = 60 * ((($r - $g) / $d) + 4);
            }
        }
        if ($h < 0) {
            $h += 360;
        }
        $s = $mx == 0 ? 0 : $d / $mx;
        return sprintf('%04x%04x%04x', (int) round($h), (int) round($s * 1000), max(10, (int) round($mx * 1000)));
    }

    private function tuyaToRgb(string $hsv): int
    {
        $h = hexdec(substr($hsv, 0, 4));
        $s = hexdec(substr($hsv, 4, 4)) / 1000;
        $v = hexdec(substr($hsv, 8, 4)) / 1000;
        $c = $v * $s;
        $x = $c * (1 - abs(fmod($h / 60, 2) - 1));
        $m = $v - $c;
        [$r, $g, $b] = $h < 60 ? [$c, $x, 0] : ($h < 120 ? [$x, $c, 0] : ($h < 180 ? [0, $c, $x] : ($h < 240 ? [0, $x, $c] : ($h < 300 ? [$x, 0, $c] : [$c, 0, $x]))));
        return ((int) round(($r + $m) * 255) << 16) | ((int) round(($g + $m) * 255) << 8) | (int) round(($b + $m) * 255);
    }
}