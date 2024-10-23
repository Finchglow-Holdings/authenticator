<?php

namespace Finchglow\Authenticator\Http\Services;

use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Backend\FIPSCrypto;


class CipherSweetEncryption
{
    protected $engine;
    protected $cipherSweet;

    /**
     * @throws CryptoOperationException
     */
    public function __construct()
    {
        $key = env('JWT_KEY', "secret");

        $this->engine = new FIPSCrypto();
        $this->cipherSweet = new CipherSweet(new StringProvider($key), $this->engine);
    }

    /**
     * Encrypt a value and store it in the database.
     *
     * @param string $table The database table.
     * @param string $column The field (column) to encrypt.
     * @param string $value The value to encrypt.
     * @return bool Success or failure.
     */
    public function encryptKey(string $table, string $column, string $value)
    {
        // Create an encrypted field (table and field names are just identifiers, not actual DB references)
        $encryptedField = new EncryptedField($this->cipherSweet, $table, $column);

        // Encrypt the value
        return $encryptedField->encryptValue($value);
    }

    /**
     * Decrypt a value from the database.
     *
     * @param string $table The database table.
     * @param string $column
     * @param string $encryptedValue The encrypted value to decrypt.
     * @return string Decrypted value.
     * @throws CryptoOperationException
     * @throws CipherSweetException
     */
    public function decryptValue(string $table, string $column, string $encryptedValue)
    {
        // Create an encrypted field (same identifiers must be used to decrypt)
        $encryptedField = new EncryptedField($this->cipherSweet, $table, $column);

        // Decrypt the value
        return $encryptedField->decryptValue($encryptedValue);
    }
}
