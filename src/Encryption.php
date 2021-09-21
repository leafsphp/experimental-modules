<?php

namespace Leaf\Experiments;

/**
 * Leaf Encryption Helper [BETA]
 * ------------------------------------------------
 * Easy encryptions
 * 
 * @author Michael Darko <mychi.darko@gmail.com>
 * @since 2.0.1
 */
class Encryption
{
	/**
	 * Key used for encryption: default generated with sodium
	 */
	protected static $key = random_bytes(32);
	protected static $nonce = random_bytes(24);

	/**
	 * Set encryption key and nonce
	 */
	public static function setKeys($key, $nonce)
	{
		static::$key = $key;
		static::$nonce = $nonce;
	
		return static::class;
	}

	/**
	 * Return the encryption key
	 */
	public static function getKeys()
	{
		return [static::$key, static::$nonce];
	}

	/**
	 * Encrypt data using Sodium
	 */
	public static function encrypt($data)
	{
		$ciphertext = sodium_crypto_secretbox($data, static::$nonce, static::$key);
		return base64_encode(static::$nonce . $ciphertext);
	}

	/**
	 * Decrypt encrypted Sodium data
	 */
	public static function decrypt($encrypted_data, $key = static::$key, $nonce = static::$nonce)
	{
		$ciphertext = mb_substr(base64_decode($encrypted_data), $nonce, null, '8bit');
		$secret_data = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
		return $secret_data;
	}
}
