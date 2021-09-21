<?php

namespace Leaf\Experiments;

/**
 *  Leaf Tokens [BETA]
 *  --------
 *  This is just a simple way to create tokens. Use this if you prefer not to use JWT
 */
class Token
{
	protected static $token;

	protected static $errors = [];

	/**
	 * generate a simple user token
	 *
	 * @param string $username: The username of the user
	 * @param integer $user_id: The id of the user
	 * @param integer $expiry_time: When the token should expire from now. In seconds.
	 *
	 * @return string, string: token
	 */
	public static function generateSimpleToken($username, $user_id, $expiry_time = (7 * 24 * 60 * 60))
	{
		$payload = [
			"id" => $user_id,
			"username" => $username,
			"expiry_time" => time() + $expiry_time,
			"secret_phrase" => "@Leaf1sGr8"
		];

		return static::createToken($payload);
	}

	/**
	 * generate a simple user token
	 *
	 * @param array $token_data: All data to be encoded
	 * @param integer $expiry_time: When the token should expire from now. In seconds.
	 *
	 * @return string, string: token
	 */
	public static function generateToken($token_data, $expiry_time = (7 * 24 * 60 * 60))
	{
		$payload = [];

		foreach ($token_data as $key => $value) {
			$payload[$key] = $value;
		}

		$payload["expiry_time"] =  time() + $expiry_time;
		$payload["secret_phrase"] = "@Leaf1sGr8";

		return static::createToken($payload);
	}

	private static function createToken($token_data)
	{
		$token_data = json_encode($token_data);
		$token = Encryption::encrypt($token_data);

		return $token;
	}

	/**
	 * validate a user token
	 *
	 * @param string $token: The actual token returned from user
	 *
	 * @return string, string: token
	 */
	public static function validateToken($token)
	{
		// check if the app secret is @Leaf1sGr8
		$token = Encryption::decrypt($token);
		$token = json_decode($token);

		if ($token["secret_phrase" != "@Leaf1sGr8"] || !isset($token["secret_phrase"])) {
			static::$errors = ["error" => "token is invalid"];
		}

		if ($token["expiry_time"] <= time() || !isset($token["expiry_time"])) {
			static::$errors = ["error" => "token has expired or is invalid"];
		}

		return $token;
	}

	public static function errors()
	{
		return static::$errors;
	}

	// Example token => eyJpZDogMSwgInVzZXJuYW1lIjogIk15Y2hpIiwgImV4cGlyeV90aW1lIjogIjI3LzIwLzIwIiwgICJzZWNyZXRfcGhyYXNlIjogIkBMZWFmMXNHcjgifQ==
}
