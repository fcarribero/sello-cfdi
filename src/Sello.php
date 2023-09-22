<?php

namespace Webneex\SelloCFDI;

use DateTime;
use DOMElement;
use Exception;

class Sello {

    /**
     * @var string $public_key
     */
    protected $public_key;

    /**
     * @var string $private_key
     */
    protected $private_key;

    /**
     * Sello constructor.
     * @param null $public_key
     * @param null $private_key
     * @param null $pass
     * @throws \Exception
     */
    public function __construct($public_key = null, $private_key = null, $pass = null) {
        if ($public_key) $this->setPublicKey($public_key);
        if ($private_key) $this->setPrivateKey($private_key, $pass);
    }

    /**
     * @param bool $pem
     * @return string
     */
    public function getPublicKey($pem = true) {
        if (!$pem) {
            return str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n", "\r"], '', $this->public_key);
        }
        return $this->public_key;
    }

    /**
     * @param string $public_key
     * @return static
     */
    public function setPublicKey($public_key) {
        if (strpos($public_key, '-----BEGIN CERTIFICATE-----') !== false) {
            $this->public_key = $public_key;
        } else {
            if (!preg_match('%^[a-zA-Z0-9/+]*={0,2}$%', $public_key)) {
                $public_key = base64_encode($public_key);
            }
            $this->public_key = '-----BEGIN CERTIFICATE-----' . "\r\n" . chunk_split($public_key, 59, "\r\n") . '-----END CERTIFICATE-----';
        }
        return $this;
    }

    /**
     * @return string
     */
    public function getPublicKeyInfo() {
        return openssl_x509_parse($this->getPublicKey());
    }

    /**
     * @return string
     */
    public function getPrivateKey($pem = true) {
        if (!$pem) {
            return str_replace(['-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----', "\n", "\r"], '', $this->private_key);
        }
        return $this->private_key;
    }

    /**
     * @param string $private_key
     * @param string|null $pass
     * @return static
     * @throws \Exception
     */
    public function setPrivateKey($private_key, $pass = null) {
        if (strpos($private_key, '-----') === 0) {
            $this->private_key = $private_key;
        } else {
            if (!$pass) throw new \Exception('Private key\'s password is required');

            file_put_contents($dir = sys_get_temp_dir() . '/' . md5(uniqid()) . '.key', $private_key);
            $private_key = shell_exec("openssl pkcs8 -inform DER -in $dir -passin pass:\"" . str_replace('$', '\\$', utf8_decode($pass)) . "\"");
            if (!$private_key) throw new \Exception('Invalid password');
            $this->private_key = $private_key;
            unlink($dir);
        }

        return $this;
    }

    /**
     * @param string $data
     * @param int $algo
     * @return string
     */
    public function sign($data, $algo = OPENSSL_ALGO_SHA1) {
        openssl_sign($data, $signature, $this->private_key, $algo);
        return base64_encode($signature);
    }

    /**
     * @param $signature_base64
     * @param $data
     * @param int $algo
     * @return bool
     */
    public function verify($signature_base64, $data, $algo = OPENSSL_ALGO_SHA1) {
        $pkey = openssl_pkey_get_public($this->getPublicKey());
        return (bool)openssl_verify($data, base64_decode($signature_base64), $pkey, $algo);
    }

    public function getPublicKeySerial() {
        $cer_info = $this->getPublicKeyInfo();
        $serial = '';
        foreach (explode("\n", chunk_split(gmp_strval($cer_info['serialNumber'], 16), 2, "\n")) as $linea) {
            if (strlen($linea) == 2) {
                $serial .= $linea[1];
            }
        }
        return $serial;
    }

    /**
     * @return DateTime|false
     */
    public function getPublicKeyValidFrom() {
        $info = $this->getPublicKeyInfo();
        return DateTime::createFromFormat('ymdHise', $info['validFrom']);
    }

    /**
     * @return DateTime|false
     */
    public function getPublicKeyValidTo() {
        $info = $this->getPublicKeyInfo();
        return DateTime::createFromFormat('ymdHise', $info['validTo']);
    }

    /**
     * @param null $now
     * @return bool
     */
    public function isValid($now = null) {
        if ($now === null) $now = new DateTime;
        return $this->getPublicKeyValidFrom() <= $now && $this->getPublicKeyValidTo() >= $now;
    }

    /**
     * @return false|string
     */
    public function toJson() {
        return json_encode([
            'public_key' => $this->getPublicKey(),
            'private_key' => $this->getPrivateKey()
        ]);
    }

    /**
     * @return mixed|string
     */
    public function getPublicKeyRFC() {
        $info = $this->getPublicKeyInfo();
        $parts = explode(' / ', $info['subject']['x500UniqueIdentifier']);
        return $parts[0];
    }

    /**
     * @return string
     */
    public function getPublicKeyName() {
        $info = $this->getPublicKeyInfo();
        return $info['subject']['name'];
    }

    /**
     * @return string
     * @throws Exception
     */
    public function getPfx() {
        file_put_contents($path_key = sys_get_temp_dir() . '/' . md5(uniqid()) . '.key', $this->getPrivateKey());
        file_put_contents($path_cer = sys_get_temp_dir() . '/' . md5(uniqid()) . '.cer', $this->getPublicKey());
        $path_pfx = sys_get_temp_dir() . '/' . md5(uniqid()) . '.pfx';
        shell_exec($CMD = "openssl pkcs12 -export -out $path_pfx -inkey $path_key -in $path_cer -passout pass: 2>&1");

        if (!($pfx = file_get_contents($path_pfx))) {
            throw new Exception('Couldn\'t build PFX file');
        }
        @unlink($path_key);
        @unlink($path_cer);
        @unlink($path_pfx);
        return base64_encode($pfx);
    }

    /**
     * @return bool
     */
    public function isFIEL() {
        $info = $this->getPublicKeyInfo();
        return $info['extensions']['keyUsage'] != "Digital Signature, Non Repudiation";
    }

    /**
     * @param $public_key
     * @param $private_key
     * @param null $pass
     * @return Sello
     * @throws Exception
     */
    public static function validateKeys($public_key, $private_key, $pass = null) {
        $sello = new Sello($public_key, $private_key, $pass);
        try {
            $test = $sello->sign('test');
        } catch (Exception $e) {
            throw new Exception('Invalid private key');
        }
        try {
            if (!$sello->verify($test, 'test')) {
                throw new Exception('Invalid key');
            }
        } catch (Exception $e) {
            throw new Exception('Invalid public key');
        }

        return $sello;
    }

    public function signXml(DOMElement $element) {
        $datos = $element->C14N(false, false, NULL, NULL);

        // obtenemos la digestion
        $digestvalue = base64_encode(hash('sha1', $datos, true));

        // creamos estructura de firma
        $signature = $element->ownerDocument->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'Signature');
        $element->appendChild($signature);
        $signedinfo = $element->ownerDocument->createElement('SignedInfo');
        $signature->appendChild($signedinfo);
        // Cannocalization
        $nn = $element->ownerDocument->createElement('CanonicalizationMethod');
        $signedinfo->appendChild($nn);
        $nn->setAttribute('Algorithm', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315');
        // SignatureMethod
        $nn = $element->ownerDocument->createElement('SignatureMethod');
        $signedinfo->appendChild($nn);
        $nn->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1');
        // Reference
        $reference = $element->ownerDocument->createElement('Reference');
        $signedinfo->appendChild($reference);
        $reference->setAttribute('URI', '');
        // Transforms
        $transforms = $element->ownerDocument->createElement('Transforms');
        $reference->appendChild($transforms);
        // Transform
        $nn = $element->ownerDocument->createElement('Transform');
        $transforms->appendChild($nn);
        $nn->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');
        $nn = $element->ownerDocument->createElement('DigestMethod');
        $reference->appendChild($nn);
        $nn->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        // DigestValue
        $nn = $element->ownerDocument->createElement('DigestValue', $digestvalue);
        $reference->appendChild($nn);
        $datos = $signedinfo->C14N(false, false, NULL, NULL);
        $signaturevalue = '';
        // firmamos los datos
        $signaturevalue_base64 = $this->sign($datos, OPENSSL_ALGO_SHA1);

        // SignatureValue
        $nn = $element->ownerDocument->createElement('SignatureValue', $signaturevalue_base64);
        $signature->appendChild($nn);
        // KeyInfo
        $keyinfo = $element->ownerDocument->createElement('KeyInfo');
        $signature->appendChild($keyinfo);
        // X509Data
        $x509data = $element->ownerDocument->createElement('X509Data');
        $keyinfo->appendChild($x509data);
        // cargamos certificado
        $nn = $element->ownerDocument->createElement('X509Certificate', $this->getPublicKey(false));
        $x509data->appendChild($nn);
    }
}