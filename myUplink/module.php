<?php

declare(strict_types=1);

class myUplink extends IPSModule
{
    private const AUTHORIZE_URL = 'https://api.myuplink.com/oauth/authorize';
    private const TOKEN_URL     = 'https://api.myuplink.com/oauth/token';
    private const REDIRECT_URL  = 'https://www.marshflattsfarm.org.uk/nibeuplink/oauth2callback/index.php';
    private const SCOPE         = 'READSYSTEM offline_access';
    private const STATE         = 'x';

    // -----------------------------------------------------------------------
    // IPS Lifecycle
    // -----------------------------------------------------------------------

    public function Create(): void
    {
        parent::Create();

        $this->RegisterPropertyString('ClientID', '');
        $this->RegisterPropertyString('ClientSecret', '');
        $this->RegisterPropertyInteger('Interval', 300);

        // Persistenter Token-Speicher (überlebt IPS-Neustart)
        $this->RegisterAttributeString('TokenData', '');

        $this->RegisterTimer(
            'UpdateTimer',
            0,
            "IPS_RequestAction(\$_IPS['TARGET'], 'Update', '');"
        );
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();

        $hasToken    = $this->ReadAttributeString('TokenData') !== '';
        $hasClientID = $this->ReadPropertyString('ClientID') !== '';

        if ($hasToken && $hasClientID) {
            $this->SetTimerInterval('UpdateTimer', $this->ReadPropertyInteger('Interval') * 1000);
            $this->SetStatus(102); // Aktiv
        } else {
            $this->SetTimerInterval('UpdateTimer', 0);
            $this->SetStatus(104); // Inaktiv
        }
    }

    public function GetConfigurationForm(): string
    {
        $clientID = $this->ReadPropertyString('ClientID');

        $authURL = $clientID !== ''
            ? self::AUTHORIZE_URL . '?' . http_build_query([
                'response_type' => 'code',
                'client_id'     => $clientID,
                'scope'         => self::SCOPE,
                'redirect_uri'  => self::REDIRECT_URL,
                'state'         => self::STATE,
            ])
            : '(Bitte zuerst Client ID eintragen und Änderungen übernehmen)';

        $hasToken = $this->ReadAttributeString('TokenData') !== '';

        return json_encode([
            'elements' => [
                [
                    'type'    => 'Label',
                    'caption' => 'API-Zugangsdaten',
                    'bold'    => true,
                ],
                [
                    'type'    => 'Label',
                    'caption' => 'myUplink Developer Portal (Client ID & Secret):',
                ],
                [
                    'type'    => 'Label',
                    'caption' => 'https://dev.myuplink.com/apps?activeTab=0',
                ],
                [
                    'type'    => 'ValidationTextBox',
                    'name'    => 'ClientID',
                    'caption' => 'Client ID',
                ],
                [
                    'type'    => 'ValidationTextBox',
                    'name'    => 'ClientSecret',
                    'caption' => 'Client Secret',
                ],
                [
                    'type'    => 'NumberSpinner',
                    'name'    => 'Interval',
                    'caption' => 'Aktualisierungsintervall (Sekunden)',
                    'minimum' => 30,
                    'maximum' => 3600,
                ],
            ],
            'actions' => [
                [
                    'type'    => 'Label',
                    'caption' => 'Token-Verwaltung',
                    'bold'    => true,
                ],
                [
                    'type'    => 'Label',
                    'caption' => $hasToken
                        ? 'Status: Token vorhanden – Aktualisierungstimer läuft.'
                        : 'Status: Noch kein Token gespeichert.',
                ],
                [
                    'type'    => 'Label',
                    'caption' => 'Schritt 1: Öffne folgenden Link im Browser und melde dich an:',
                ],
                [
                    'type'    => 'Label',
                    'caption' => $authURL,
                ],
                [
                    'type'    => 'Label',
                    'caption' => 'Schritt 2: Nach der Anmeldung wirst du weitergeleitet. Kopiere den Wert des Parameters "code=..." aus der Browser-Adresszeile und füge ihn hier ein:',
                ],
                [
                    'type'    => 'ValidationTextBox',
                    'name'    => 'AuthCode',
                    'caption' => 'Authorization Code',
                ],
                [
                    'type'    => 'Button',
                    'caption' => 'Token anfordern und speichern',
                    'onClick' => 'MYU_RequestToken($id, $AuthCode);',
                ],
                [
                    'type'    => 'Label',
                    'caption' => '',
                ],
                [
                    'type'    => 'Button',
                    'caption' => 'Jetzt aktualisieren',
                    'onClick' => 'MYU_Update($id);',
                ],
            ],
            'status' => [
                [
                    'code'    => 102,
                    'icon'    => 'active',
                    'caption' => 'Aktiv',
                ],
                [
                    'code'    => 104,
                    'icon'    => 'inactive',
                    'caption' => 'Inaktiv – Token fehlt oder Client ID nicht gesetzt',
                ],
            ],
        ]);
    }

    public function RequestAction($ident, $value): void
    {
        match ($ident) {
            'Update' => $this->Update(),
            default  => throw new RuntimeException("Unbekannte Action: $ident"),
        };
    }

    // -----------------------------------------------------------------------
    // Öffentliche Modul-Funktionen (aufrufbar als MYU_*)
    // -----------------------------------------------------------------------

    public function RequestToken(string $authCode): void
    {
        $this->SendDebug('RequestToken', 'Authorization Code empfangen (Länge: ' . strlen($authCode) . ')', 0);

        if (strlen($authCode) < 60) {
            $this->SendDebug('RequestToken', 'Fehler: Code zu kurz', 0);
            echo 'Fehler: Authorization Code ist zu kurz oder ungültig.';
            return;
        }

        $this->SendDebug('RequestToken', 'Sende Token-Anfrage an: ' . self::TOKEN_URL, 0);

        $response = $this->doPost(self::TOKEN_URL, [
            'grant_type'    => 'authorization_code',
            'code'          => $authCode,
            'client_id'     => $this->ReadPropertyString('ClientID'),
            'client_secret' => $this->ReadPropertyString('ClientSecret'),
            'redirect_uri'  => self::REDIRECT_URL,
        ]);

        if ($response === null || ($response['token_type'] ?? '') !== 'Bearer') {
            $this->SendDebug('RequestToken', 'Fehler: Ungültige API-Antwort', 0);
            echo 'Fehler: Token-Anfrage fehlgeschlagen. Bitte Authorization Code prüfen.';
            return;
        }

        $this->SendDebug('RequestToken', 'Token erfolgreich empfangen (token_type: ' . $response['token_type'] . ', expires_in: ' . ($response['expires_in'] ?? '?') . 's)', 0);
        $this->WriteAttributeString('TokenData', json_encode($response));
        $this->ApplyChanges();

        echo 'Token erfolgreich gespeichert. Aktualisierungstimer wurde gestartet.';
    }

    public function Update(): void
    {
        $this->SendDebug('Update', 'Update gestartet um ' . date('H:i:s'), 0);

        $tokenData = $this->loadToken();
        if ($tokenData === null) {
            $this->SendDebug('Update', 'Fehler: Kein Token vorhanden', 0);
            $this->LogMessage('Kein Token vorhanden – bitte zuerst Token anfordern.', KL_ERROR);
            return;
        }

        $this->SendDebug('Update', 'Token geladen, sende Anfrage an systems/me', 0);
        $accessToken = $tokenData['access_token'] ?? '';
        $result      = $this->doGet('https://api.myuplink.com/v2/systems/me', $accessToken);

        $this->SendDebug('GET systems/me', 'HTTP ' . $result['status'], 0);

        if ($result['status'] === 401) {
            $this->SendDebug('Update', 'Token abgelaufen (401), starte Refresh...', 0);
            $this->LogMessage('Token abgelaufen, starte Refresh...', KL_WARNING);
            $tokenData = $this->refreshToken($tokenData);
            if ($tokenData === null) {
                $this->SendDebug('Update', 'Token-Refresh fehlgeschlagen', 0);
                $this->LogMessage('Token-Refresh fehlgeschlagen.', KL_ERROR);
                return;
            }
            $this->SendDebug('Update', 'Token-Refresh erfolgreich, wiederhole Anfrage', 0);
            $accessToken = $tokenData['access_token'];
            $result      = $this->doGet('https://api.myuplink.com/v2/systems/me', $accessToken);
            $this->SendDebug('GET systems/me (retry)', 'HTTP ' . $result['status'], 0);
        }

        if ($result['status'] !== 200) {
            $this->SendDebug('Update', 'Fehler: HTTP ' . $result['status'] . ' bei systems/me', 0);
            $this->LogMessage("API-Fehler HTTP {$result['status']} bei systems/me.", KL_ERROR);
            return;
        }

        $systems = $result['body']['systems'] ?? [];
        $this->SendDebug('Update', count($systems) . ' System(e) gefunden', 0);

        foreach ($systems as $system) {
            $systemName = $system['name'] ?? $system['systemId'] ?? '?';
            $devices    = $system['devices'] ?? [];
            $this->SendDebug('System', '"' . $systemName . '" – ' . count($devices) . ' Gerät(e)', 0);

            foreach ($devices as $device) {
                $deviceID   = $device['id'];
                $deviceName = $device['product']['name'] ?? $deviceID;
                $pointsURL  = 'https://api.myuplink.com/v2/devices/' . $deviceID . '/points';

                $this->SendDebug('GET points', $deviceName . ' → ' . $pointsURL, 0);
                $pResult = $this->doGet($pointsURL, $accessToken);
                $this->SendDebug('GET points', 'HTTP ' . $pResult['status'] . ' – ' . count($pResult['body']) . ' Parameter', 0);

                if ($pResult['status'] === 200) {
                    foreach ($pResult['body'] as $point) {
                        $this->syncVariable($point);
                    }
                }
            }
        }

        $this->SendDebug('Update', 'Update abgeschlossen um ' . date('H:i:s'), 0);
        $this->LogMessage('Update erfolgreich um ' . date('H:i:s') . '.', KL_MESSAGE);
    }

    // -----------------------------------------------------------------------
    // Private Hilfsfunktionen
    // -----------------------------------------------------------------------

    private function loadToken(): ?array
    {
        $raw = $this->ReadAttributeString('TokenData');
        if ($raw === '') return null;
        $data = json_decode($raw, true);
        return is_array($data) ? $data : null;
    }

    private function refreshToken(array $old): ?array
    {
        $this->SendDebug('refreshToken', 'Sende Refresh-Anfrage an: ' . self::TOKEN_URL, 0);

        $response = $this->doPost(self::TOKEN_URL, [
            'grant_type'    => 'refresh_token',
            'client_id'     => $this->ReadPropertyString('ClientID'),
            'client_secret' => $this->ReadPropertyString('ClientSecret'),
            'refresh_token' => $old['refresh_token'] ?? '',
        ]);

        if ($response === null) {
            $this->SendDebug('refreshToken', 'Fehler: Keine gültige Antwort erhalten', 0);
            return null;
        }

        $this->SendDebug('refreshToken', 'Neuer Token empfangen, expires_in: ' . ($response['expires_in'] ?? '?') . 's', 0);
        $this->WriteAttributeString('TokenData', json_encode($response));
        return $response;
    }

    private function doGet(string $url, string $token): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => ["Authorization: Bearer $token"],
        ]);
        $body     = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($httpCode !== 200) {
            $this->SendDebug('doGet', 'Fehler HTTP ' . $httpCode . ' für URL: ' . $url . ' – Antwort: ' . $body, 0);
        }

        return ['status' => $httpCode, 'body' => json_decode($body, true) ?? []];
    }

    private function doPost(string $url, array $fields): ?array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query($fields),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        ]);
        $body     = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($httpCode !== 200) {
            $this->SendDebug('doPost', 'Fehler HTTP ' . $httpCode . ' für URL: ' . $url . ' – Antwort: ' . $body, 0);
        }

        return $httpCode === 200 ? (json_decode($body, true) ?? null) : null;
    }

    private function syncVariable(array $point): void
    {
        $paramId   = (string) ($point['parameterId'] ?? '');
        $paramName = (string) ($point['parameterName'] ?? $paramId);
        $value     = $point['value'] ?? null;

        if ($paramId === '') return;

        $ident     = 'p_' . preg_replace('/\W/', '_', $paramId);
        $labelName = $paramId . ' ' . $paramName;

        $this->SendDebug('syncVariable', $labelName . ' = ' . $value . ' ' . ($point['parameterUnit'] ?? ''), 0);

        if (is_numeric($value)) {
            $this->RegisterVariableFloat($ident, $labelName, '', 0);
            $this->SetValue($ident, (float) $value);
        } else {
            $this->RegisterVariableString($ident, $labelName, '', 0);
            $this->SetValue($ident, (string) ($value ?? ''));
        }
    }
}
