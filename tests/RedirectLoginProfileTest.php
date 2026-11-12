<?php

use Brain\Monkey;
use Brain\Monkey\Functions;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;

require_once WPA0_PLUGIN_DIR . 'lib/php-jwt/Authentication/JWT.php';

/**
 * Tests for the user profile lookup in WP_Auth0_LoginManager::redirect_login() (#3004).
 *
 * A non-200 or malformed response from the Management API (or /userinfo) used to be
 * json_decoded and passed to login_user() as the profile, which then reported
 * "This account does not have an email associated".
 */
class RedirectLoginProfileTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    private const ID_TOKEN_SUB = 'auth0|69fa0a51a63fd732ded01af4';
    private const ACCESS_TOKEN = 'access-token-secret-value';

    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();
        ini_set( 'error_log', '/dev/null' );

        Patchwork\redefine( 'WP_Auth0_Api_Client::get_info_headers', function () {
            return array();
        } );

        Functions\when( 'wp_remote_retrieve_response_code' )->alias( function ( $r ) {
            return $r['response']['code'] ?? '';
        } );
        Functions\when( 'wp_remote_retrieve_header' )->alias( function ( $r, $h ) {
            return $r['headers'][ $h ] ?? '';
        } );
        Functions\when( 'wp_remote_retrieve_body' )->alias( function ( $r ) {
            return $r['body'] ?? '';
        } );
        Functions\when( 'admin_url' )->justReturn( 'https://example.test/wp-admin/' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.test/wp-login.php' );
        Functions\when( 'home_url' )->justReturn( 'https://example.test' );
        Functions\when( 'get_option' )->justReturn( array() );
        Functions\stubEscapeFunctions();
        Functions\stubTranslationFunctions();

        $_REQUEST['auth0'] = '1';
        $_REQUEST['code'] = 'the-auth-code';
        $_REQUEST['state'] = '';
        $GLOBALS['wp_query'] = null;
    }

    protected function tearDown(): void
    {
        unset( $_REQUEST['auth0'], $_REQUEST['code'], $_REQUEST['state'] );
        $GLOBALS['wp_query'] = null;

        Monkey\tearDown();
        parent::tearDown();
    }

    private function idToken(): string
    {
        return JWT::encode( array( 'sub' => self::ID_TOKEN_SUB, 'aud' => 'client-id' ), 'secret' );
    }

    private function response( int $code, string $body, array $headers = array() ): array
    {
        return array( 'response' => array( 'code' => $code ), 'headers' => $headers, 'body' => $body );
    }

    /** Partial mock whose login_user() records the profile and throws a sentinel instead of reaching exit(). */
    private function makeManager( int $loginUserCalls = 0 ): WP_Auth0_LoginManager
    {
        $a0_options = Mockery::mock( 'WP_Auth0_Options' );
        $a0_options->shouldReceive( 'get' )->with( 'domain' )->andReturn( 'example.auth0.com' );
        $a0_options->shouldReceive( 'get' )->with( 'client_id' )->andReturn( 'client-id' );
        $a0_options->shouldReceive( 'get' )->with( 'client_secret' )->andReturn( 'secret' );
        $a0_options->shouldReceive( 'get_client_secret_as_key' )->andReturn( 'secret' );
        $a0_options->shouldReceive( 'get_client_signing_algorithm' )->andReturn( 'HS256' );

        $manager = Mockery::mock( WP_Auth0_LoginManager::class, array( Mockery::mock( 'WP_Auth0_UsersRepo' ), $a0_options ) )->makePartial();
        $manager->shouldReceive( 'login_user' )->times( $loginUserCalls )->andReturnUsing( function ( $userinfo ) {
            throw new LoginUserReached( $userinfo );
        } );
        return $manager;
    }

    /** Stub the token exchange and the profile call. */
    private function stubHttp( bool $withIdToken, array $profileResponse ): void
    {
        $token = array( 'access_token' => self::ACCESS_TOKEN );
        if ( $withIdToken ) {
            $token['id_token'] = $this->idToken();
        }
        Functions\expect( 'wp_remote_post' )->once()->andReturn( $this->response( 200, json_encode( $token ) ) );
        Functions\expect( 'wp_remote_get' )->once()->andReturn( $profileResponse );
    }

    /** @return array{0: string, 1: array, 2: int} wp_die message, args, update_option call count */
    private function runAndCaptureDie(): array
    {
        $captured = array();
        $logged = array();
        Functions\expect( 'update_option' )->once()->andReturnUsing( function ( $name, $value ) use ( &$logged ) {
            $logged = array( $name, $value );
        } );
        Functions\expect( 'wp_die' )->once()->andReturnUsing( function ( $msg, $title = '', $args = array() ) use ( &$captured ) {
            $captured = array( $msg, $args );
        } );

        $this->makeManagerForDie->init_auth0();

        return array( $captured[0], $captured[1], $logged );
    }

    private $makeManagerForDie;

    private function assertFriendlyFailure( array $result, string $expectedCode ): void
    {
        list( $msg, $args, $logged ) = $result;

        $this->assertSame( array( 'response' => 400 ), $args );
        $this->assertStringContainsString( 'try logging in again', $msg );
        $this->assertStringNotContainsString( 'does not have an email', $msg );

        $this->assertSame( 'auth0_error_log', $logged[0] );
        $this->assertSame( 'init_auth0_userinfo', $logged[1][0]['section'] );
        $this->assertSame( $expectedCode, (string) $logged[1][0]['code'] );

        $entry = json_encode( $logged[1][0] );
        $this->assertStringNotContainsString( self::ACCESS_TOKEN, $entry );
        $this->assertStringNotContainsString( 'eyJ', $entry, 'No JWT may be logged.' );
        $this->assertStringNotContainsString( 'the-auth-code', $entry );
    }

    public static function failureStatuses(): array
    {
        return array( 'rate limited' => array( 429 ), 'unauthorized' => array( 401 ), 'forbidden' => array( 403 ), 'server error' => array( 500 ) );
    }

    #[PHPUnit\Framework\Attributes\DataProvider( "failureStatuses" )]
    public function test_management_api_non_200_returns_friendly_400_and_logs( int $status ): void
    {
        $body = json_encode( array( 'statusCode' => $status, 'error' => 'Too Many Requests', 'message' => 'The current_user scope limit has been reached' ) );
        $this->stubHttp( true, $this->response( $status, $body, array( 'x-ratelimit-remaining' => '0', 'x-ratelimit-reset' => '1700000000' ) ) );
        $this->makeManagerForDie = $this->makeManager( 0 );

        $this->assertFriendlyFailure( $this->runAndCaptureDie(), (string) $status );
    }

    public function test_userinfo_branch_429_returns_friendly_400_and_logs(): void
    {
        $this->stubHttp( false, $this->response( 429, '{"error":"too_many_requests"}', array( 'x-ratelimit-remaining' => '0' ) ) );
        $this->makeManagerForDie = $this->makeManager( 0 );

        $this->assertFriendlyFailure( $this->runAndCaptureDie(), '429' );
    }

    public static function malformedBodies(): array
    {
        return array(
            'not json' => array( '<html>oops</html>' ),
            'no sub or user_id' => array( '{"name":"x"}' ),
            'json scalar' => array( '"hello"' ),
        );
    }

    #[PHPUnit\Framework\Attributes\DataProvider( "malformedBodies" )]
    public function test_200_with_malformed_profile_returns_friendly_400_and_logs( string $body ): void
    {
        $this->stubHttp( true, $this->response( 200, $body ) );
        $this->makeManagerForDie = $this->makeManager( 0 );

        $this->assertFriendlyFailure( $this->runAndCaptureDie(), '200' );
    }

    public function test_failure_writes_status_and_rate_limit_headers_to_error_log(): void
    {
        $logFile = tempnam( sys_get_temp_dir(), 'a0log' );
        ini_set( 'error_log', $logFile );
        $this->stubHttp( true, $this->response( 429, '{"error":"x"}', array( 'x-ratelimit-remaining' => '0', 'x-ratelimit-reset' => '1700000000' ) ) );
        $this->makeManagerForDie = $this->makeManager( 0 );

        $this->runAndCaptureDie();

        $contents = file_get_contents( $logFile );
        unlink( $logFile );
        ini_set( 'error_log', '/dev/null' );

        $this->assertStringContainsString( 'HTTP 429', $contents );
        $this->assertStringContainsString( 'x-ratelimit-remaining=0', $contents );
        $this->assertStringContainsString( 'x-ratelimit-reset=1700000000', $contents );
        $this->assertStringNotContainsString( self::ACCESS_TOKEN, $contents );
        $this->assertStringNotContainsString( 'eyJ', $contents );
    }

    public function test_200_with_valid_profile_reaches_login_user(): void
    {
        $profile = array( 'user_id' => self::ID_TOKEN_SUB, 'email' => 'editor@example.test', 'email_verified' => true );
        $this->stubHttp( true, $this->response( 200, json_encode( $profile ) ) );
        $manager = $this->makeManager( 1 );

        try {
            $manager->redirect_login();
            $this->fail( 'login_user() was not reached.' );
        } catch ( LoginUserReached $e ) {
            $this->assertSame( 'editor@example.test', $e->userinfo->email );
            $this->assertSame( self::ID_TOKEN_SUB, $e->userinfo->user_id );
        }
    }

    public function test_userinfo_branch_200_with_sub_reaches_login_user(): void
    {
        $this->stubHttp( false, $this->response( 200, json_encode( array( 'sub' => self::ID_TOKEN_SUB, 'email' => 'editor@example.test' ) ) ) );
        $manager = $this->makeManager( 1 );

        try {
            $manager->redirect_login();
            $this->fail( 'login_user() was not reached.' );
        } catch ( LoginUserReached $e ) {
            $this->assertSame( self::ID_TOKEN_SUB, $e->userinfo->sub );
        }
    }
}

class LoginUserReached extends Exception
{
    public $userinfo;

    public function __construct( $userinfo )
    {
        parent::__construct( 'login_user reached' );
        $this->userinfo = $userinfo;
    }
}

if ( ! class_exists( 'WP_Error' ) ) {
    /** Minimal stand-in for core's WP_Error; only what WP_Auth0_ErrorManager reads. */
    class WP_Error
    {
        private $code;
        private $message;

        public function __construct( $code = '', $message = '' )
        {
            $this->code = $code;
            $this->message = $message;
        }

        public function get_error_code()
        {
            return $this->code;
        }

        public function get_error_message()
        {
            return $this->message;
        }
    }
}
