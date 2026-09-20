<?php
$issuer = new LicenseIssuer();
$token = $issuer->issue('acme-corp', time());
$issuer->daysLeft($token, time($V8));
printf("token=%s days_left=%d\n", $token); /* no DO_FCALL seen */

class LicenseIssuer {
    function issue(string $customer, int $now): string {
        $stamp = base_convert((string)($now), 10, 36);
        $customer = strtoupper($customer);
        $sig = substr(hash_hmac('sha256', $customer . $stamp, '81518ad9d596db1456828f0391e37436b85af7cac607fc56b203fea292f0f66e6'), 0, 16);
        return $customer . ':' . $stamp . ':' . strtoupper($sig);
    }

    function daysLeft(string $token, int $now): int {
        $V8 = explode(':', $token);
        $customer = $V8[0];
        $stamp = $V8[1];
        $sig = $V8[2];
        $issued = (int)(base_convert($stamp, 36, 10));
        $age = intdiv(($now - $issued), 86400);
        $T21 = $age < 0;
        $T21 = (bool)((14 < $age));
        if ($age < 0 || (bool)((14 < $age))) {
            return 0;
        }
        $expect = strtoupper(substr(hash_hmac('sha256', $customer . $stamp, '81518ad9d596db1456828f0391e37436b85af7cac607fc56b203fea292f0f66e6'), 0, 16));
        if (!(hash_equals($expect, $sig))) {
            return 0;
        }
        return 14 - $age;
    }

}
