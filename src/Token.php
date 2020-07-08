<?php
declare( strict_types=1 );

namespace FWSPlugin\Authentication;

use Exception;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use GraphQL\Error\Error;
use stdClass;

/**
 * Class ManageToken
 *
 * @package FWSPlugin\Authentication
 * @author  Boris Djemrovski <boris@forwardslashny.com>
 */
class Token
{

	/** @var string */
	private $secretKey;

	/** @var User */
	private $user;

	/** @var string */
	private $iss;

	/** @var int */
	private $issued;

	/** @var int */
	private $nbf;

	/** @var string */
	private $sessionID;

	/** @var int */
	private $expiration;

	/** @var bool */
	private $isValid = false;

	/** @var string */
	private $errorMessage;

	/** @var string */
	private $errorCode;

	/**
	 * Token constructor.
	 *
	 * @param string $token
	 *
	 * @throws Error
	 */
	public function __construct( string $token = '' )
	{
		$secret_key = defined( 'FWS_GRAPHQL_AUTH_SECRET_KEY' ) ? FWS_GRAPHQL_AUTH_SECRET_KEY : '';
		$this->secretKey = apply_filters( 'fws_graphql_auth_secret_key', $secret_key );

		if ( empty( $this->secretKey ) || ! is_string( $this->secretKey ) ) {
			throw new Error( 'Secret Key is not defined.' );
		}

		// If token is provided, parse and validate it
		if ( $token !== '' ) {
			$this->parseToken( $token );

		} // If not, create new with default params
		else {
			$this->setDefaults();
		}
	}

	/**
	 * Set default values
	 */
	private function setDefaults(): void
	{
		$this->iss = get_bloginfo( 'url' );
		$this->issued = time();
		$this->nbf = $this->issued;
		$this->expiration = $this->issued + apply_filters( 'graphql_jwt_auth_expire', 300 );
	}

	/**
	 * Parse and validate the token string
	 *
	 * @param string $token
	 */
	private function parseToken( string $token ): void
	{
		$tks = explode( '.', $token );
		$payload = JWT::jsonDecode( JWT::urlsafeB64Decode( $tks[1] ) );

		// Check for user ID
		if ( ! isset( $payload->data->user_id ) ) {
			$this->errorCode = 'invalid-jwt';
			$this->errorMessage = __( 'User ID not found in the token', 'fws-graphql-authentication' );

			return;
		}

		$user = new User( get_userdata( $payload->data->user_id ) );

		JWT::$leeway = 5;

		// Try decoding
		try {
			$jwt = JWT::decode( $token, $this->secretKey, [ 'HS256' ] );

		} // Catch if token has expired, validate session for the user and refresh
		catch ( ExpiredException $e ) {

			// Check if session is present
			if ( ! isset( $payload->data->session ) ) {
				$this->errorCode = 'invalid-jwt';
				$this->errorMessage = __( 'Session ID is missing', 'fws-graphql-authentication' );

				return;
			}

			// Check if session is valid
			if ( ! $user->checkSession( $payload->data->session ) ) {
				$this->errorCode = 'invalid-jwt';
				$this->errorMessage = __( 'Session is not valid or expired. Please login again.', 'fws-graphql-authentication' );

				return;
			}

			// Everything passed, generate new token and set response headers
			$jwt = $this->refresh( $payload, $user );

		} // Catch all other Exceptions
		catch ( \Exception $e ) {
			$this->errorCode = 'invalid-jwt-secret-key';
			$this->errorMessage = $e->getMessage();

			return;
		}

		// Check the ISS
		if ( ! isset( $jwt->iss ) || get_bloginfo( 'url' ) !== $jwt->iss ) {
			$this->errorCode = 'invalid-jwt';
			$this->errorMessage = __( 'The iss do not match with this server', 'fws-graphql-authentication' );

			return;
		}

		$this->sessionID = $payload->data->session;
		$this->user = $user;
		$this->isValid = true;
	}

	/**
	 * @param stdClass $payload
	 *
	 * @param User     $user
	 *
	 * @return stdClass
	 */
	private function refresh( stdClass $payload, User $user ): stdClass
	{
		// Generate new token
		$token = new Token();
		$token->setSessionID( $payload->data->session );
		$token->setUser( $user );

		add_filter( 'graphql_response_headers_to_send',
			function ( $headers ) use ( $token ) {

				$headers[ 'X-Session-Update' ] = $token->encode();
				$headers[ 'Access-Control-Expose-Headers' ] = 'X-Session-Update';

				return $headers;
			},
			10,
			1
		);

		return $token->buildObject();
	}

	/**
	 * @return string
	 */
	public function getErrorMessage(): string
	{
		return $this->errorMessage;
	}

	/**
	 * @return string
	 */
	public function getErrorCode(): string
	{
		return $this->errorCode;
	}

	/**
	 * @param User $user
	 *
	 * @return $this
	 */
	public function setUser( User $user ): self
	{
		$this->user = $user;

		return $this;
	}

	/**
	 * @return int
	 */
	public function getNBF(): int
	{
		return $this->nbf;
	}

	/**
	 * @return $this
	 * @throws Exception
	 */
	public function generateSessionID(): self
	{
		$this->sessionID = bin2hex( random_bytes( 16 ) );

		return $this;
	}

	/**
	 * Encodes the JWT token string for publishing
	 *
	 * @return string
	 */
	public function encode(): string
	{
		return JWT::encode( $this->buildArray(), $this->secretKey );
	}

	/**
	 * @return array
	 */
	private function buildArray(): array
	{
		return [
			'iss' => $this->getISS(),
			'iat' => $this->getIssued(),
			'nbf' => $this->getNBF(),
			'exp' => $this->getExpiration(),
			'data' => [
				'user_id' => $this->user->getID(),
				'session' => $this->getSessionID(),
			],
		];
	}

	/**
	 * @param array $array
	 *
	 * @return object
	 */
	private function buildObject( array $array = [] ): object
	{
		if ( empty( $array ) ) {
			$array = $this->buildArray();
		}

		$object = new stdClass();

		foreach ( $array as $key => $value ) {
			if ( is_array( $value ) ) {
				$value = $this->buildObject( $value );
			}

			$object->$key = $value;
		}

		return $object;
	}

	/**
	 * @return string
	 */
	public function __toString(): string
	{
		return $this->encode();
	}

	/**
	 * @return int
	 */
	private function getExpiration(): int
	{
		return $this->expiration;
	}

	/**
	 * @return int
	 */
	private function getIssued(): int
	{
		return $this->issued;
	}

	/**
	 * @return string
	 */
	public function getISS(): string
	{
		return $this->iss;
	}

	/**
	 * @param string $sessionID
	 *
	 * @return Token
	 */
	public function setSessionID( string $sessionID ): Token
	{
		$this->sessionID = $sessionID;

		return $this;
	}

	/**
	 * @return string
	 */
	public function getSessionID(): string
	{
		return $this->sessionID;
	}

	/**
	 * @return User
	 */
	public function getUser(): User
	{
		return $this->user;
	}

	/**
	 * @return bool
	 */
	public function isValid(): bool
	{
		return $this->isValid;
	}
}