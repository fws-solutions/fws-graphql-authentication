<?php
declare( strict_types=1 );

namespace FWSPlugin\Authentication;

use WP_User;

/**
 * Class User
 *
 * @package FWSPlugin\Authentication
 * @author  Boris Djemrovski <boris@forwardslashny.com>
 */
class User
{

	/** @var WP_User */
	private $wpUser;

	/** @var string */
	private $jwtSecret;

	/**
	 * User constructor.
	 *
	 * @param WP_User $user
	 */
	public function __construct( WP_User $user )
	{
		$this->wpUser = $user;
	}

	/**
	 * @return int
	 */
	public function getID(): int
	{
		return $this->wpUser->ID;
	}

	/**
	 * @param string $uuid
	 */
	public function newSession( string $uuid ): void
	{
		update_user_meta( $this->getID(), 'fws_session_' . $uuid, $this->getJwtSecret() );
	}

	/**
	 * @param string $sessionID
	 *
	 * @return bool
	 */
	public function checkSession( string $sessionID ): bool
	{
		$exists = get_user_meta( $this->getID(), 'fws_session_' . $sessionID, true );

		// If session does not exist or if it is old
		if ( empty( $exists ) || $exists !== $this->getJwtSecret() ) {
			$this->cleanOldSessions();

			return false;
		}

		return true;
	}

	/**
	 * Destroys a single session based on the session ID
	 *
	 * @param string $sessionID
	 *
	 * @return bool
	 */
	public function destroySession( string $sessionID = '' ): bool
	{
		return delete_user_meta( $this->getID(), 'fws_session_' . $sessionID );
	}

	/**
	 * This will regenerate the JWT secret key for the user and remove all sessions
	 */
	public function destroyAllSessions(): void
	{
		$this->issueNewSecret();
		$this->cleanOldSessions();
	}

	/**
	 * This will loop through all sessions for the user and
	 */
	public function cleanOldSessions(): void
	{
		$metas = get_user_meta( $this->getID() );

		foreach ( $metas as $key => $value ) {

			// Skip non-session metas
			if ( substr( $key, 0, strlen( 'fws_session_' ) ) !== 'fws_session_' ) {
				continue;
			}

			// Skip if session is valid
			if ( $value === $this->getJwtSecret() ) {
				continue;
			}

			// Delete if obsolete
			delete_user_meta( $this->getID(), $key );
		}
	}

	/**
	 * Returns the user's JWT secret
	 *
	 * @return string
	 */
	private function getJwtSecret(): string
	{
		if ( empty( $this->jwtSecret ) ) {
			$this->jwtSecret = get_user_meta( $this->getID(), 'fws_auth_jwt_secret', true );
		}

		if ( empty( $this->jwtSecret ) || ! is_string( $this->jwtSecret ) ) {
			$this->issueNewSecret();
		}

		return $this->jwtSecret;
	}

	/**
	 * Issue a new JWT Auth Secret
	 *
	 * @return string
	 */
	private function issueNewSecret(): string
	{
		$this->jwtSecret = uniqid( 'fws_auth_jwt_', true );
		update_user_meta( $this->getID(), 'fws_auth_jwt_secret', $this->jwtSecret );

		return $this->jwtSecret;
	}
}