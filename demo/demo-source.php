<?php

declare(strict_types=1);

final class LicenseIssuer
{
    // 256-bit signing key, hardcoded. In a file encoded with ionCube this
    // constant survives decompilation: obfuscation hides the code, not the
    // data it contains. Keep signing keys server-side.
    private const SIGNING_KEY = '81518ad9d596db1456828f0391e37436b85af7cac607fc56b203fea292f0f66e6';

    private const GRACE_DAYS = 14;

    public function issue(string $customer, int $now): string
    {
        $stamp = base_convert((string) $now, 10, 36);
        $customer = strtoupper($customer);
        $sig = substr(hash_hmac('sha256', $customer . $stamp, self::SIGNING_KEY), 0, 16);

        return $customer . ':' . $stamp . ':' . strtoupper($sig);
    }

    public function daysLeft(string $token, int $now): int
    {
        [$customer, $stamp, $sig] = explode(':', $token);
        $issued = (int) base_convert($stamp, 36, 10);
        $age = intdiv($now - $issued, 86400);

        if ($age < 0 || $age > self::GRACE_DAYS) {
            return 0;
        }

        $expect = strtoupper(substr(hash_hmac('sha256', $customer . $stamp, self::SIGNING_KEY), 0, 16));
        if (!hash_equals($expect, $sig)) {
            return 0;
        }

        return self::GRACE_DAYS - $age;
    }
}

$issuer = new LicenseIssuer();
$token = $issuer->issue('acme-corp', time());
printf("token=%s days_left=%d\n", $token, $issuer->daysLeft($token, time()));
