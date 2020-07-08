<?php
declare( strict_types=1 );
/**
 * Plugin Name: FWS Graphql Authentication
 * Plugin URI:
 * Description: Authentication functionality for WPGraphQL
 * Author: Boris Djemrovski
 * Author URI:
 * Text Domain: fws-graphql-authentication
 * Version: 0.0.1
 * Requires at least: 4.7.0
 * Tested up to: 4.8.3
 * Requires PHP: 7.2
 * License: GPL-3
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 *
 * @package FWSPlugin
 */

namespace FWSPlugin;

use FWSPlugin\Authentication\User;
use FWSPlugin\Authentication\Token;
use GraphQL\Error\Error;
use GraphQL\Error\UserError;
use GraphQL\Executor\ExecutionResult;
use GraphQL\Type\Definition\ResolveInfo;
use WPGraphQL\AppContext;
use WPGraphQL\Data\Loader\UserLoader;

if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class Authentication
 *
 * @package FWSPlugin
 * @author  Boris Djemrovski <boris@forwardslashny.com>
 */
final class Authentication
{

	/** @var self */
	private static $instance;

	/**
	 * Authentication constructor.
	 */
	private function __construct()
	{
	}

	/**
	 * @return Authentication
	 */
	public static function instance()
	{
		if ( ! self::$instance instanceof Authentication ) {
			self::$instance = new Authentication;

			self::$instance->setupConstants();
			self::$instance->includes();
			self::$instance->hooks();

			/**
			 * Fire off init action
			 *
			 * @param Authentication $instance The instance of the Authentication class
			 */
			do_action( 'fws_graphql_authentication_init', self::$instance );
		}

		/**
		 * Return the Authentication Instance
		 */
		return self::$instance;
	}

	/**
	 * Setup plugin constants.
	 *
	 * @access private
	 * @return void
	 * @since  0.0.1
	 */
	private function setupConstants()
	{
		// Plugin version.
		if ( ! defined( 'FWS_GRAPHQL_AUTHENTICATION_VERSION' ) ) {
			define( 'FWS_GRAPHQL_AUTHENTICATION_VERSION', '0.0.1' );
		}

		// Plugin Folder Path.
		if ( ! defined( 'FWS_GRAPHQL_AUTHENTICATION_PLUGIN_DIR' ) ) {
			define( 'FWS_GRAPHQL_AUTHENTICATION_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
		}

		// Plugin Folder URL.
		if ( ! defined( 'FWS_GRAPHQL_AUTHENTICATION_PLUGIN_URL' ) ) {
			define( 'FWS_GRAPHQL_AUTHENTICATION_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
		}

		// Plugin Root File.
		if ( ! defined( 'FWS_GRAPHQL_AUTHENTICATION_PLUGIN_FILE' ) ) {
			define( 'FWS_GRAPHQL_AUTHENTICATION_PLUGIN_FILE', __FILE__ );
		}
	}

	/**
	 * Include required files.
	 * Uses composer's autoload
	 *
	 * @access private
	 * @return void
	 * @since  0.0.1
	 */
	private function includes()
	{
		// Autoload Required Classes.
		require_once( FWS_GRAPHQL_AUTHENTICATION_PLUGIN_DIR . 'vendor/autoload.php' );
	}

	/**
	 * Initialize the plugin hooks
	 */
	private function hooks()
	{
		// Filter how WordPress determines the current user.
		add_filter(
			'determine_current_user',
			[ '\FWSPlugin\Authentication', 'filterDetermineCurrentUser' ],
			99
		);

		// Register the "login" mutation to the Schema.
		add_action(
			'graphql_register_types',
			[ '\FWSPlugin\Authentication', 'registerMutationLogin' ],
			10
		);

		// Register the "logout" mutation to the Schema.
		add_action(
			'graphql_register_types',
			[ '\FWSPlugin\Authentication', 'registerMutationLogout' ],
			10
		);

		// When the GraphQL Request is initiated, validate the token.
		add_action(
			'init_graphql_request',
			[ '\FWSPlugin\Authentication', 'actionValidateToken' ],
			10
		);

		// Make sure proper status code is returned in the case of the error
		add_filter( 'graphql_response_status_code',
			[ '\FWSPlugin\Authentication', 'graphqlResponseStatusCode' ],
			10,
			2
		);
	}

	/**
	 * Filter the $status_code before setting the headers
	 *
	 * @param int             $status_code The status code to apply to the headers
	 * @param ExecutionResult $response    The response of the GraphQL Request
	 *
	 * @return int
	 */
	public static function graphqlResponseStatusCode( int $status_code, ExecutionResult $response ): int
	{

		if ( empty( $response->errors ) ) {
			return $status_code;
		}

		$jwtError = false;

		foreach ( $response->errors as $error ) {
			$jwtError = strpos( $error->getMessage(), 'jwt' ) !== false ? true : $jwtError;
		}

		if ( $jwtError ) {
			return 403;
		}

		// Return $status_code if not set to 200, or change to 500 for unknown error
		return $status_code !== 200 ? $status_code : 500;
	}

	/**
	 * @throws Error
	 */
	public static function actionValidateToken()
	{
		$jwt = self::getTokenFromHeaders();

		if ( empty( $jwt ) ) {
			return;
		}

		$token = new Token( $jwt );

		if ( $token->isValid() ) {
			return;
		}

		add_action( 'graphql_before_resolve_field',
			function () use ( $token ) {
				throw new UserError( $token->getErrorCode() . ' | ' . $token->getErrorMessage() );
			},
			1
		);
	}

	/**
	 * Middleware tries to authenticate the user using the token in the headers
	 *
	 * @param int|bool|null $userID
	 *
	 * @return int|bool
	 * @throws Error
	 */
	public static function filterDetermineCurrentUser( $userID )
	{
		$tokenHeader = self::getTokenFromHeaders();

		// If token header doesn't exist, ignore
		if ( empty( $tokenHeader ) ) {
			return $userID;
		}

		$token = new Token( $tokenHeader );

		// If token is not valid, ignore
		if ( ! $token->isValid() ) {
			return $userID;
		}

		return $token->getUser()->getID();
	}

	/**
	 * Registers Login Mutation
	 */
	public static function registerMutationLogin(): void
	{
		register_graphql_mutation(
			'login',
			[
				'description' => __( 'Login a user. Request for an authToken and User details in response', 'fws-graphql-authentication' ),
				'inputFields' => [
					'username' => [
						'type' => [ 'non_null' => 'String' ],
						'description' => __( 'The username used for login. Typically a unique or email address depending on specific configuration', 'fws-graphql-authentication' ),
					],
					'password' => [
						'type' => [ 'non_null' => 'String' ],
						'description' => __( 'The plain-text password for the user logging in.', 'fws-graphql-authentication' ),
					],
				],
				'outputFields' => [
					'authToken' => [
						'type' => 'String',
						'description' => __( 'JWT Token that can be used in future requests for Authentication', 'fws-graphql-authentication' ),
					],
					'user' => [
						'type' => 'User',
						'description' => __( 'The user that was logged in', 'fws-graphql-authentication' ),
					],
				],
				'mutateAndGetPayload' => function ( $input, AppContext $context, ResolveInfo $info ) {

					$wpUser = wp_authenticate( sanitize_user( $input['username'] ), trim( $input['password'] ) );

					// Authentication error
					if ( is_wp_error( $wpUser ) ) {
						$error_code = ! empty( $wpUser->get_error_code() ) ? $wpUser->get_error_code() : 'invalid login';
						throw new UserError( __( esc_html( $error_code ), 'fws-graphql-authentication' ) );
					}

					// Unknown error
					if ( empty( $wpUser->data->ID ) ) {
						throw new UserError( __( 'The user could not be found', 'fws-graphql-authentication' ) );
					}

					wp_set_current_user( $wpUser->data->ID );

					$user = new User( wp_get_current_user() );

					// Create JWT Token
					$token = new Token();
					$token->setUser( $user )
					      ->generateSessionID();

					// Store new session
					$user->newSession( $token->getSessionID() );

					/** @var UserLoader $userLoader */
					$userLoader = $context->get_loader( 'user' );

					// Response object
					return [
						'authToken' => $token->encode(),
						'user' => $userLoader->load( $user->getID() ),
						'id' => $user->getID(),
					];
				},
			]
		);
	}

	/**
	 * Registers Logout Mutation
	 */
	public static function registerMutationLogout(): void
	{
		register_graphql_mutation(
			'logout',
			[
				'description' => __( 'Logout a user.', 'fws-graphql-authentication' ),
				'outputFields' => [
					'success' => [
						'type' => 'Boolean',
						'description' => __( 'Whether logout was successful', 'fws-graphql-authentication' ),
					],
				],
				'mutateAndGetPayload' => function ( $input, AppContext $context, ResolveInfo $info ) {

					$token = new Token( self::getTokenFromHeaders() );

					// Invalid Token
					if ( ! $token->isValid() ) {
						throw new UserError( $token->getErrorCode() . ' | ' . $token->getErrorMessage() );
					}

					// Response object
					return [
						'success' => $token->getUser()->destroySession( $token->getSessionID() ),
					];
				},
			]
		);
	}

	/**
	 * Tries to obtain the token from request headers
	 *
	 * @return string
	 */
	private static function getTokenFromHeaders(): string
	{
		$token = '';

		$authHeader = self::getAuthHeader();

		// If there's no $auth, return an error
		if ( ! empty( $authHeader ) ) {
			[ $token ] = sscanf( $authHeader, 'Bearer %s' );
		}

		return $token;
	}

	/**
	 * Checks multiple $_SERVER keys for authentication headers
	 *
	 * @return string
	 */
	private static function getAuthHeader(): string
	{
		$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? ( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '' );

		/**
		 * Return the auth header, pass through a filter
		 *
		 * @param string $authHeader The header used to authenticate a user's HTTP request
		 */
		return apply_filters( 'fws_graphql_auth_get_auth_header', $authHeader );
	}
}

/**
 * Start JWT_Authentication.
 */
function init()
{
	return Authentication::instance();
}

add_action( 'plugins_loaded', '\FWSPlugin\init', 1 );
