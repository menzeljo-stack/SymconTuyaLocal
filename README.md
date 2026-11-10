# Tuya Local für IP-Symcon

Steuert Tuya-WLAN-Geräte (Leuchten, Schalter, Steckdosen) **lokal** über das Tuya-Protokoll 3.3, 3.4 und 3.5 – ohne Cloud.

## Module

- **Tuya Gerät (lokal)** (`TUYA`): ein Gerät. Geräte-ID, Local Key und IP oder MAC eintragen. Die Protokollversion wird automatisch erkannt.
  - Leuchten (DP 20–24): Status, Helligkeit, Farbtemperatur, Farbe
  - Schalter und Steckdosen (DP 1–9)
  - `TUYA_Update($id)`, `TUYA_SetDPs($id, ['20' => true])`
- **Tuya Konfigurator** (`TUYACFG`): liest mit Access ID und Secret aus einem Tuya-IoT-Cloud-Projekt alle Geräte samt Local Key und MAC ein und legt sie per Klick an. Die Cloud wird nur zum Einlesen genutzt.
  - `TUYACFG_UpdateKeys($id)` aktualisiert die Local Keys nach erneutem Anlernen.

## Local Key

Der Local Key steht nur in der Tuya-Cloud. Zugang über iot.tuya.com: Cloud-Projekt (Smart Home, passendes Rechenzentrum) anlegen und die Smart-Life-App unter „Devices → Link App Account“ verknüpfen.
