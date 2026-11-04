<?php

declare(strict_types=1);

/**
 * Verification suite for the Torv3 client.
 *
 * Run: php tests/run.php
 *
 * Covers the checks listed in the project brief plus the official hs-ntor
 * test vectors from rend-spec-v3 Appendix G.1 and the HKDF vectors from
 * proposal 216.
 */

require __DIR__ . '/../autoload.php';

use Torv3\Cell\Commands;
use Torv3\Circuit\Circuit;
use Torv3\Crypto\Aes128Ctr;
use Torv3\Crypto\Ed25519;
use Torv3\Crypto\Keccak;
use Torv3\Crypto\NtorHandshake;
use Torv3\Onion\OnionV3;

$passed = 0;
$failed = 0;

function check(string $name, bool $condition, string $detail = ''): void
{
    global $passed, $failed;

    if ($condition) {
        $passed++;
        echo "  PASS  {$name}\n";
    } else {
        $failed++;
        echo "  FAIL  {$name}" . ($detail !== '' ? " ({$detail})" : '') . "\n";
    }
}

function section(string $title): void
{
    echo "\n{$title}\n" . str_repeat('-', strlen($title)) . "\n";
}

/* ==========================================================================
 * 1. ntor key layout and HKDF (proposal 216 test vectors)
 * ========================================================================== */

section('1. ntor handshake / HKDF-SHA256 key layout');

$vector1 = 'd3490ed48b12a48f9547861583573fe3f19aafe3f81dc7fc75eeed96d741b3290f941576c1f9f0b2d463d1ec7ab2c6bf71cdd7f826c6298c00dbfe6711635d7005f0269493edf6046cc7e7dcf6abe0d20c77cf363e8ffe358927817a3d3e73712cee28d8';
$derived1 = bin2hex(NtorHandshake::hkdf('', NtorHandshake::T_KEY, NtorHandshake::M_EXPAND, 100));
check('HKDF test vector (empty IKM)', $vector1 === $derived1, $derived1);

$vector2 = '5521492a85139a8d9107a2d5c0d9c91610d0f95989975ebee6c02a4f8d622a6cfdf9b7c7edd3832e2760ded1eac309b76f8d66c4a3c4d6225429b3a016e3c3d45911152fc87bc2de9630c3961be9fdb9f93197ea8e5977180801926d3321fa21513e59ac';
$derived2 = bin2hex(NtorHandshake::hkdf('Tor', NtorHandshake::T_KEY, NtorHandshake::M_EXPAND, 100));
check('HKDF test vector ("Tor")', $vector2 === $derived2, $derived2);

$vector3 = 'a2aa9b50da7e481d30463adb8f233ff06e9571a0ca6ab6df0fb206fa34e5bc78d063fc291501beec53b36e5a0e434561200c5f8bd13e0f88b3459600b4dc21d69363e2895321c06184879d94b18f078411be70b767c7fc40679a9440a0c95ea83a23efbf';
$derived3 = bin2hex(NtorHandshake::hkdf(
    'AN ALARMING ITEM TO FIND ON YOUR CREDIT-RATING STATEMENT',
    NtorHandshake::T_KEY,
    NtorHandshake::M_EXPAND,
    100
));
check('HKDF test vector (long IKM)', $vector3 === $derived3, $derived3);

// Full handshake: client keys must equal the server-side derivation and the
// key slice must be Df[0:20] | Db[20:40] | Kf[40:56] | Kb[56:72].
$nodeId = random_bytes(20);
$server = NtorHandshake::generateKeypair();
$onionKey = $server['public'];
$client = NtorHandshake::generateKeypair();

$serverResult = NtorHandshake::serverRespond($nodeId, $server['private'], $onionKey, $client['public']);
$replyY = substr($serverResult['reply'], 0, 32);
$replyAuth = substr($serverResult['reply'], 32, 32);

$clientKeys = NtorHandshake::clientComputeKeys(
    $nodeId,
    $onionKey,
    $client['private'],
    $client['public'],
    $replyY,
    $replyAuth
);

check('ntor client/server Df agree', $clientKeys['df'] === $serverResult['df']);
check('Df is keys[0:20]', strlen($clientKeys['df']) === 20);
check('Db is keys[20:40]', strlen($clientKeys['db']) === 20);
check('Kf is keys[40:56]', strlen($clientKeys['kf']) === 16);
check('Kb is keys[56:72]', strlen($clientKeys['kb']) === 16);
check('ntor AUTH is verified', $clientKeys['kf'] === $serverResult['kf'] && $clientKeys['kb'] === $serverResult['kb']);

$tampered = false;
try {
    NtorHandshake::clientComputeKeys(
        $nodeId,
        $onionKey,
        $client['private'],
        $client['public'],
        $replyY,
        str_repeat("\x00", 32)
    );
} catch (\Torv3\TorProtocolException) {
    $tampered = true;
}
check('ntor rejects a bad AUTH', $tampered);

/* ==========================================================================
 * 2. AES-128-CTR
 * ========================================================================== */

section('2. AES-128-CTR relay-cell keystream');

$key = random_bytes(16);
$cipher = new Aes128Ctr($key);
$zeros = str_repeat("\x00", 16);
$expectedBlock0 = openssl_encrypt($zeros, 'aes-128-ctr', $key, OPENSSL_RAW_DATA, $zeros);
check('block 0 == AES-CTR(IV=0, zeros)[0:16]', substr($cipher->encrypt($zeros), 0, 16) === $expectedBlock0);

$key2 = random_bytes(16);
$streamed = new Aes128Ctr($key2);
$multi = $streamed->encrypt(str_repeat('A', 100)) . $streamed->encrypt(str_repeat('B', 100));
$oneShot = openssl_encrypt(str_repeat('A', 100) . str_repeat('B', 100), 'aes-128-ctr', $key2, OPENSSL_RAW_DATA, $zeros);
check('stateful stream matches one-shot CTR', $multi === $oneShot);

$hundred = new Aes128Ctr($key2);
$chunks = '';
foreach (str_split(str_repeat('C', 509), 37) as $piece) {
    $chunks .= $hundred->encrypt($piece);
}
check('509-byte cell split across calls', $chunks === openssl_encrypt(str_repeat('C', 509), 'aes-128-ctr', $key2, OPENSSL_RAW_DATA, $zeros));

$hsCipher = new Aes128Ctr(random_bytes(32));
check('AES-256 mode for hs-ntor layer', strlen($hsCipher->encrypt($zeros)) === 16);

/* ==========================================================================
 * 3. v3 onion address checksum and base32
 * ========================================================================== */

section('3. v3 onion address encoding');

$identity = random_bytes(32);
$address = OnionV3::encodeAddress($identity);
$parsedAddress = OnionV3::parseAddress($address);

check('address checksum = SHA3-256(".onion checksum"|pk|0x03)[0:2]', $parsedAddress['checksum'] === substr(Keccak::sha3_256('.onion checksum' . $identity . "\x03"), 0, 2));
check('parsed public key round-trips', $parsedAddress['publicKey'] === $identity);
check('version byte is 3', $parsedAddress['version'] === 3);
check('address ends in .onion', str_ends_with($address, '.onion'));

$example = 'pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion';
$exampleParsed = OnionV3::parseAddress($example);
check('spec example address parses', strlen($exampleParsed['publicKey']) === 32);
check('spec example re-encodes', OnionV3::encodeAddress($exampleParsed['publicKey']) === $example);

$badChecksum = false;
try {
    $raw = OnionV3::base32Decode(str_replace('.onion', '', $example));
    $raw[32] = chr(ord($raw[32]) ^ 0xFF);
    OnionV3::parseAddress(OnionV3::base32Encode($raw) . '.onion');
} catch (\Torv3\TorOnionException) {
    $badChecksum = true;
}
check('corrupted checksum is rejected', $badChecksum);

/* ==========================================================================
 * 4. Base32: 35 bytes -> 56 characters
 * ========================================================================== */

section('4. Base32 address length');

$thirtyFive = random_bytes(35);
$encoded = OnionV3::base32Encode($thirtyFive);
check('35 bytes encode to exactly 56 chars', strlen($encoded) === 56, (string) strlen($encoded));
check('base32 round-trips', OnionV3::base32Decode($encoded) === $thirtyFive);
check('alphabet is lowercase RFC4648', preg_match('/^[a-z2-7]{56}$/', $encoded) === 1);

/* ==========================================================================
 * 5. Ed25519 certificate parsing + group arithmetic
 * ========================================================================== */

section('5. Ed25519 certificate and scalar multiplication');

$certKey = random_bytes(32);
$certificate = "\x01" . "\x08" . pack('N', intdiv(time(), 3600) + 1) . "\x01" . $certKey . "\x00" . random_bytes(64);
$pem = "-----BEGIN ED25519 CERT-----\n"
    . chunk_split(base64_encode($certificate), 64, "\n")
    . "-----END ED25519 CERT-----\n";

check('certified key at byte offset 7', OnionV3::certKey($pem) === $certKey);

// Ed25519 group operations: k*B must match libsodium's public key derivation.
$seed = random_bytes(32);
$keypair = sodium_crypto_sign_seed_keypair($seed);
$secretScalar = substr(hash('sha512', $seed, true), 0, 32);
$secretScalar[0] = chr(ord($secretScalar[0]) & 248);
$secretScalar[31] = chr((ord($secretScalar[31]) & 63) | 64);

$basePointBytes = hex2bin(Ed25519::BASE_POINT);
$derivedPublic = Ed25519::scalarMultiply($secretScalar, $basePointBytes);
check('scalarMultiply matches libsodium public key', hash_equals(sodium_crypto_sign_publickey($keypair), $derivedPublic));

$one = Ed25519::scalarMultiply("\x01" . str_repeat("\x00", 31), $basePointBytes);
check('1 * B == B', bin2hex($one) === Ed25519::BASE_POINT);

// Group law: a*(b*P) == (a*b mod L)*P
$p = OnionV3::parseAddress($example)['publicKey'];
$a = random_bytes(32);
$b = random_bytes(32);
$nested = Ed25519::scalarMultiply($a, Ed25519::scalarMultiply($b, $p));
$product = gmp_mod(
    gmp_mul(gmp_import($a, 1, GMP_LSW_FIRST), gmp_import($b, 1, GMP_LSW_FIRST)),
    Ed25519::order()
);
$productBytes = str_pad(gmp_export($product, 1, GMP_LSW_FIRST), 32, "\x00", STR_PAD_RIGHT);
check('scalar multiplication is associative', $nested === Ed25519::scalarMultiply($productBytes, $p));

/* ==========================================================================
 * 6. Descriptor layer MAC is verified before decryption
 * ========================================================================== */

section('6. HSv3 descriptor layer encryption');

// A real onion service key is a valid Ed25519 point, so derive one properly.
$validIdentity = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(random_bytes(32)));
$onion = new OnionV3(OnionV3::encodeAddress($validIdentity));
$revision = 42;
$layerPlaintext = 'create2-formats 2' . "\n" . 'encrypted' . "\n";
$salt = random_bytes(16);

$secretInput = $onion->blindedPublicKeyValue() . $onion->subcredential() . pack('J', $revision);
$keys = Keccak::shake256($secretInput . $salt . 'hsdir-encrypted-data', 80);
$layerKey = substr($keys, 0, 32);
$layerIv = substr($keys, 32, 16);
$layerMacKey = substr($keys, 48, 32);

$layerCiphertext = openssl_encrypt($layerPlaintext, 'aes-256-ctr', $layerKey, OPENSSL_RAW_DATA, $layerIv);
$layerMac = Keccak::sha3_256(pack('J', 32) . $layerMacKey . pack('J', 16) . $salt . $layerCiphertext);
$blob = $salt . $layerCiphertext . $layerMac;

check(
    'layer MAC = SHA3-256(len|MAC_KEY|len|salt|ciphertext) verifies',
    $onion->decryptLayer($blob, $onion->blindedPublicKeyValue(), 'hsdir-encrypted-data', $revision) === $layerPlaintext
);

$tamperedBlob = $blob;
$tamperedBlob[40] = chr(ord($tamperedBlob[40]) ^ 0x01);
$macRejected = false;
try {
    $onion->decryptLayer($tamperedBlob, $onion->blindedPublicKeyValue(), 'hsdir-encrypted-data', $revision);
} catch (\Torv3\TorOnionException $e) {
    $macRejected = str_contains($e->getMessage(), 'MAC');
}
check('tampered ciphertext fails MAC before decrypt', $macRejected);

$wrongConstant = false;
try {
    $onion->decryptLayer($blob, $onion->blindedPublicKeyValue(), 'hsdir-superencrypted-data', $revision);
} catch (\Torv3\TorOnionException) {
    $wrongConstant = true;
}
check('wrong layer constant fails MAC', $wrongConstant);

/* ==========================================================================
 * 7. hs-ntor: INTRODUCE1 vector and RENDEZVOUS2 derivation
 * ========================================================================== */

section('7. hs-ntor INTRODUCE1 / RENDEZVOUS2');

// Official vector from rend-spec-v3 Appendix G.1.
$x = hex2bin('60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341');
$xPub = hex2bin('BF04348B46D09AED726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5D');
$b = hex2bin('8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979');
$authKey = hex2bin('34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F');
$subcred = hex2bin('0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57');
$introducePlaintext = hex2bin(
    '6BD364C12638DD5C3BE23D76ACA05B04E6CE932C0101000100200DE6130E4FCAC4EDDA24E21220CC3EADAE403EF6B7D11C8273AC71908DE565450300067F00000113890214F823C4F8CC085C792E0AEE0283FE00AD7520B37D0320728D5DF39B7B7077A0118A900FF4456C382F0041300ACF9C58E51C392795EF87'
);

$secret = sodium_crypto_scalarmult($x, $b) . $authKey . $xPub . $b . OnionV3::PROTOID;
$hsKeys = Keccak::shake256($secret . OnionV3::T_HSENC . OnionV3::M_HSEXPAND . $subcred, 64);
check(
    'INTRODUCE1 ENC_KEY matches official vector',
    bin2hex(substr($hsKeys, 0, 32)) === '9b8917ba3d05f3130dacce5300c3dc27f6d012912f1c733036f822d0ed238706'
);
check(
    'INTRODUCE1 MAC_KEY matches official vector',
    bin2hex(substr($hsKeys, 32, 32)) === 'fc4058da59d4df61e7b40985d122f502fd59336bc21c30caf5e7f0d4a2c38fd5'
);

$introduceCiphertext = openssl_encrypt(
    $introducePlaintext,
    'aes-256-ctr',
    substr($hsKeys, 0, 32),
    OPENSSL_RAW_DATA,
    str_repeat("\x00", 16)
);
check(
    'INTRODUCE1 ciphertext (AES-256-CTR, zero IV) matches vector',
    str_starts_with(
        bin2hex($introduceCiphertext),
        'adbecccb38e378304dcc179d3d9e437b452af5702ced2ccfec085bc02c4c175f'
    )
);

// MAC over the published body itself: H(56) | X(32) | C | M(32).
$publishedBody = hex2bin(
    '000000000000000000000000000000000000000002002034E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F00'
    . 'BF04348B46D09AED726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5D'
    . 'ADBECCCB38E378304DCC179D3D9E437B452AF5702CED2CCFEC085BC02C4C175F'
    . 'A446525C1B9D5530563C362FDFFB802DAB8CD9EBC7A5EE17DA62E37DEEB0EB18'
    . '7FBB48C63298B0E83F391B7566F42ADC97C46BA7588278273A44CE96BC68FFDA'
    . 'E31EF5F0913B9A9C7E0F173DBC0BDDCD4ACB4C4600980A7DDD9EAEC6E7F3FA3F'
    . 'C37CD95E5B8BFB3E35717012B78B4930569F895CB349A07538E42309C993223A'
    . 'EA77EF8AEA64F25DDEE97DA623F1AEC0A47F150002150455845C385E5606E41A'
    . '9A199E7111D54EF2D1A51B7554D8B3692D85AC587FB9E69DF990EFB776D8'
);
$publishedHeader = substr($publishedBody, 0, 56);
$publishedClientPk = substr($publishedBody, 56, 32);
$publishedMac = substr($publishedBody, -32);
$publishedCiphertext = substr($publishedBody, 88, -32);

check('published INTRODUCE1 X matches vector', $publishedClientPk === $xPub);
$publishedPlaintext = openssl_decrypt(
    $publishedCiphertext,
    'aes-256-ctr',
    substr($hsKeys, 0, 32),
    OPENSSL_RAW_DATA,
    str_repeat("\x00", 16)
);
check(
    'published INTRODUCE1 ciphertext decrypts with ENC_KEY',
    is_string($publishedPlaintext) && substr($publishedPlaintext, 0, 20) === hex2bin('6BD364C12638DD5C3BE23D76ACA05B04E6CE932C')
);
check(
    'INTRODUCE1 MAC matches vector',
    Keccak::sha3_256(pack('J', 32) . substr($hsKeys, 32, 32) . $publishedHeader . $publishedClientPk . $publishedCiphertext) === $publishedMac
);

// RENDEZVOUS2: EXP_1 uses the introduction ephemeral key, EXP_2 the fresh key.
$yPub = hex2bin('8FBE0DB4D4A9C7FF46701E3E0EE7FD05CD28BE4F302460ADDEEC9E93354EE700');
$expectedAuth = '4a92e8437b8424d5e5ec279245d5c72b25a0327acf6daf902079fcb643d8b208';
$expectedSeed = '4d0c72fe8aff35559d95ecc18eb5a36883402b28cdfd48c8a530a5a3d7d578db';

$rendContext = [
    'clientPrivate' => $x,
    'clientPublic' => $xPub,
    'encKey' => $b,
    'authKey' => $authKey,
];
$rendKeys = $onion->processRend2($rendContext, $yPub . hex2bin($expectedAuth));
check('RENDEZVOUS2 AUTH verifies', bin2hex($rendKeys['seed']) === $expectedSeed, bin2hex($rendKeys['seed']));
check('HS layer keys are 32 bytes each', strlen($rendKeys['kf']) === 32 && strlen($rendKeys['kb']) === 32 && strlen($rendKeys['df']) === 32);

$badRend = false;
try {
    $onion->processRend2($rendContext, $yPub . str_repeat("\x11", 32));
} catch (\Torv3\TorOnionException) {
    $badRend = true;
}
check('RENDEZVOUS2 rejects a bad AUTH', $badRend);

// INTRODUCE1 builder: layout and plaintext round-trip.
$introKeys = NtorHandshake::generateKeypair();
$rendezvousKeys = NtorHandshake::generateKeypair();
$cookie = random_bytes(20);
$specs = [
    ['type' => 0x00, 'data' => inet_pton('127.0.0.1') . pack('n', 9001)],
    ['type' => 0x02, 'data' => random_bytes(20)],
];
$built = $onion->buildIntroduce1(
    ['authKey' => $introKeys['public'], 'encKey' => $introKeys['public']],
    $rendezvousKeys['public'],
    $specs,
    $cookie
);

check('INTRODUCE1 body header is 20 zero bytes | 0x02 | len | auth key | 0x00', substr($built['body'], 0, 20) === str_repeat("\x00", 20)
    && ord($built['body'][20]) === 2
    && unpack('n', $built['body'], 21)[1] === 32
    && substr($built['body'], 23, 32) === $introKeys['public']
    && ord($built['body'][55]) === 0);

// Recompute the hs-ntor keys for this instance and decrypt our own cell.
$builtSecret = sodium_crypto_scalarmult($built['clientPrivate'], $introKeys['public']) . $introKeys['public'] . $built['clientPublic'] . $introKeys['public'] . OnionV3::PROTOID;
$builtKeys = Keccak::shake256($builtSecret . OnionV3::T_HSENC . OnionV3::M_HSEXPAND . $onion->subcredential(), 64);
$builtCiphertext = substr($built['body'], 88, -32);
$builtMac = substr($built['body'], -32);
$expectedBuiltMac = Keccak::sha3_256(
    pack('J', 32) . substr($builtKeys, 32, 32) . substr($built['body'], 0, 56) . $built['clientPublic'] . $builtCiphertext
);
check('built INTRODUCE1 MAC verifies', hash_equals($expectedBuiltMac, $builtMac));

$builtPlaintext = openssl_decrypt($builtCiphertext, 'aes-256-ctr', substr($builtKeys, 0, 32), OPENSSL_RAW_DATA, str_repeat("\x00", 16));
check('built INTRODUCE1 plaintext starts with cookie', substr($builtPlaintext, 0, 20) === $cookie);
check('built INTRODUCE1 carries ntor rendezvous key', substr($builtPlaintext, 24, 32) === $rendezvousKeys['public']);
check('built INTRODUCE1 carries 2 link specifiers', ord($builtPlaintext[56]) === 2);
check('built INTRODUCE1 plaintext is a multiple of 16 bytes', strlen($builtPlaintext) % 16 === 0);

/* ==========================================================================
 * 8. HSDir fetches use RELAY_BEGIN_DIR
 * ========================================================================== */

section('8. HSDir fetches use RELAY_BEGIN_DIR');

$onionSource = file_get_contents(__DIR__ . '/../src/Onion/OnionV3.php') ?: '';
check('RELAY_BEGIN_DIR constant is 13', Commands::RELAY_BEGIN_DIR === 13);
check('fetchDescriptor opens a BEGIN_DIR stream', preg_match('/beginStream\(\s*\'\'\s*,\s*0\s*,\s*true/', $onionSource) === 1);
check('descriptor path is /tor/hs/3/<id>', str_contains($onionSource, "'/tor/hs/3/'"));

/* ==========================================================================
 * 9. RELAY_EXTEND2 uses RELAY_EARLY
 * ========================================================================== */

section('9. Circuit extension uses RELAY_EARLY');

$circuitSource = file_get_contents(__DIR__ . '/../src/Circuit/Circuit.php') ?: '';
check('EXTEND2 is sent with $early = true', preg_match('/RELAY_EXTEND2[^\n]*,\s*true\s*\)/', $circuitSource) === 1);
check('RELAY_EARLY limit is enforced', str_contains($circuitSource, 'MAX_RELAY_EARLY'));
check('RELAY_EARLY command is 9', Commands::RELAY_EARLY === 9);

/* ==========================================================================
 * 10. SENDME v1 payload
 * ========================================================================== */

section('10. Authenticated SENDME v1');

$tag = random_bytes(20);
$payload = Circuit::sendmePayload($tag);
check('SENDME payload is 1 + 2 + 20 bytes', strlen($payload) === 23);
check('SENDME version is 0x01', ord($payload[0]) === 1);
check('SENDME DATA_LEN is 20', unpack('n', $payload, 1)[1] === 20);
check('SENDME tag is the 20-byte rolling digest', substr($payload, 3) === $tag);

$sendmeCell = \Torv3\Cell\RelayCell::build(Commands::RELAY_SENDME, 0, $payload);
check('SENDME fits a relay cell', \Torv3\Cell\RelayCell::length($sendmeCell) === 23);

check(
    'hs index uses INT_8(replica) (tor hs_indexes vector)',
    bin2hex(OnionV3::storeAtIndex(str_repeat("\x42", 32), 1, 42, 1440))
        === '37e5cbbd56a22823714f18f1623ece5983a0d64c78495a8cfab854245e5f9a8a'
);
check(
    'HSDir index matches tor hs_indexes vector',
    bin2hex(\Torv3\TorClient::hsdirIndex(str_repeat("\x42", 32), str_repeat("\x43", 32), 42, 1440))
        === 'db475361014a09965e7e5e4d4a25b8f8d4b8f16cb1d8a7e95eed50249cc1a2d5'
);

check(
    'SRV selection uses the previous value before the run midpoint',
    \Torv3\TorClient::selectSharedRandom(strtotime('2026-11-01 06:00:00 UTC'), 1440, 'current', 'previous') === 'previous'
);
check(
    'SRV selection uses the current value after the run midpoint',
    \Torv3\TorClient::selectSharedRandom(strtotime('2026-11-01 13:00:00 UTC'), 1440, 'current', 'previous') === 'current'
);
check(
    'SRV selection falls back to current without a previous value',
    \Torv3\TorClient::selectSharedRandom(strtotime('2026-11-01 06:00:00 UTC'), 1440, 'current', null) === 'current'
);

/* ==========================================================================
 * Extra: Keccak, PEM extraction, link specifiers, descriptors
 * ========================================================================== */

section('Extra: Keccak, descriptor parsing, link specifiers');

check('SHA3-256("")', bin2hex(Keccak::sha3_256('')) === 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a');
check('SHA3-256("abc") matches ext-hash', bin2hex(Keccak::sha3_256('abc')) === hash('sha3-256', 'abc'));
$randomBlock = random_bytes(1000);
check('SHA3-256 multi-block matches ext-hash', Keccak::sha3_256($randomBlock) === hash('sha3-256', $randomBlock, true));
check('SHAKE-256("", 32)', bin2hex(Keccak::shake256('', 32)) === '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f');
check('SHAKE-256("abc", 64)', bin2hex(Keccak::shake256('abc', 64)) === '483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4');

$pemText = "superencrypted\n-----BEGIN MESSAGE-----\n" . chunk_split(base64_encode(random_bytes(64)), 64, "\n") . "-----END MESSAGE-----\nsignature abc\n";
check('superencrypted PEM block decodes', strlen((string) OnionV3::extractPemBlock($pemText, 'superencrypted')) === 64);
check('inner "encrypted" block decodes', strlen((string) OnionV3::extractPemBlock("encrypted\n-----BEGIN MESSAGE-----\n" . chunk_split(base64_encode(random_bytes(32)), 64, "\n") . "-----END MESSAGE-----\n", 'encrypted')) === 32);

$specList = [
    ['type' => 0x00, 'data' => inet_pton('10.0.0.1') . pack('n', 443)],
    ['type' => 0x02, 'data' => random_bytes(20)],
    ['type' => 0x03, 'data' => random_bytes(32)],
];
$encodedSpecs = OnionV3::encodeLspecs($specList);
check(
    'link specifiers round-trip (with NSPEC prefix)',
    OnionV3::parseLspecs(base64_encode(chr(count($specList)) . $encodedSpecs)) === $specList
);

$introDescriptor = "introduction-point " . base64_encode(chr(count($specList)) . $encodedSpecs) . "\n"
    . "onion-key ntor " . rtrim(base64_encode(random_bytes(32)), '=') . "\n"
    . "auth-key\n"
    . "-----BEGIN ED25519 CERT-----\n"
    . chunk_split(base64_encode("\x01\x08" . pack('N', intdiv(time(), 3600) + 1) . "\x01" . random_bytes(32) . "\x00" . random_bytes(64)), 64, "\n")
    . "-----END ED25519 CERT-----\n"
    . "enc-key ntor " . rtrim(base64_encode(random_bytes(32)), '=') . "\n"
    . "enc-key-cert\n"
    . "-----BEGIN ED25519 CERT-----\n"
    . chunk_split(base64_encode("\x01\x0b" . pack('N', intdiv(time(), 3600) + 1) . "\x01" . random_bytes(32) . "\x00" . random_bytes(64)), 64, "\n")
    . "-----END ED25519 CERT-----\n";

$introPoints = OnionV3::parseIntroPoints($introDescriptor);
check('intro point parsed from descriptor plaintext', count($introPoints) === 1);
check('intro point auth key extracted', strlen($introPoints[0]['authKey'] ?? '') === 32);
check('intro point enc key extracted', strlen($introPoints[0]['encKey'] ?? '') === 32);
check('intro point link specifiers parsed', count($introPoints[0]['linkSpecifiers']) === 3);

// Time period and descriptor id are deterministic per period.
$periodNow = OnionV3::timePeriod(1460546101);
check('time period matches spec example (16903)', $periodNow === 16903, (string) $periodNow);

$first = $onion->hsIndex(1);
$second = $onion->hsIndex(2);
check('hs index depends on replica', $first !== $second && strlen($first) === 32);
$expectedPath = '/tor/hs/3/' . rtrim(base64_encode($onion->blindedPublicKeyValue()), '=');
check('descriptor path is unpadded base64 of the blinded key', $onion->descriptorPath() === $expectedPath);
check(
    'descriptor path carries 43 base64 characters',
    strlen(substr($onion->descriptorPath(), strlen('/tor/hs/3/'))) === 43
);

section('Extra: descriptor signing-key certificate and signature');

function edKeypair(): array
{
    // PHP builds differ: some return ['publickey' => ..., 'secretkey' => ...],
    // others return sk(64) . pk(32), others only the 64-byte sk = seed . pk.
    $pair = sodium_crypto_sign_seed_keypair(random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES));

    if (is_array($pair)) {
        return [$pair['publickey'], $pair['secretkey']];
    }
    if (strlen($pair) >= 96) {
        return [substr($pair, 64), substr($pair, 0, 64)];
    }

    return [substr($pair, 32), $pair];
}

[$blindedPk, $blindedSk] = edKeypair();
[$descPk, $descSk] = edKeypair();

$certBody = "\x01\x08" . pack('N', intdiv(time(), 3600) + 1) . "\x01" . $descPk . "\x01"
    . pack('n', 32) . "\x04\x00" . $blindedPk;
$certRaw = $certBody . sodium_crypto_sign_detached($certBody, $blindedSk);
$certPem = "-----BEGIN ED25519 CERT-----\n"
    . chunk_split(base64_encode($certRaw), 64, "\n")
    . "-----END ED25519 CERT-----\n";

$parsedCert = OnionV3::parseEd25519Cert($certPem);
check('cert parser returns the certified key', $parsedCert['key'] === $descPk);
check('cert parser returns the signing-key extension', ($parsedCert['extensions'][4] ?? '') === $blindedPk);

$body = "hs-descriptor 3\nversion 3\n"
    . "descriptor-signing-key-cert\n" . $certPem
    . "revision-counter 1\n";
$sig = sodium_crypto_sign_detached('Tor onion service descriptor sig v3' . $body, $descSk);
$descriptor = $body . 'signature ' . base64_encode($sig) . "\n";

$ok = true;
try {
    OnionV3::verifyDescriptorForBlindedKey($descriptor, $blindedPk);
} catch (Throwable $e) {
    $ok = false;
}
check('valid descriptor signature is accepted', $ok);

$tampered = str_replace('revision-counter 1', 'revision-counter 2', $descriptor);
$rejected = false;
try {
    OnionV3::verifyDescriptorForBlindedKey($tampered, $blindedPk);
} catch (Throwable $e) {
    $rejected = true;
}
check('tampered descriptor signature is rejected', $rejected);

$wrongKey = false;
try {
    OnionV3::verifyDescriptorForBlindedKey($descriptor, random_bytes(32));
} catch (Throwable $e) {
    $wrongKey = true;
}
check('descriptor certificate from another service is rejected', $wrongKey);

check(
    'client-authorization requirement is detected',
    OnionV3::introAuthRequired("introduction-point abc\nintro-auth-required ed25519\n")
);
check(
    'descriptors without client auth are accepted',
    !OnionV3::introAuthRequired("introduction-point abc\nintroduction-point def\n")
);

/* ==========================================================================
 * Summary
 * ========================================================================== */

echo "\n" . str_repeat('=', 50) . "\n";
echo "Passed: {$passed}   Failed: {$failed}\n";

exit($failed === 0 ? 0 : 1);
