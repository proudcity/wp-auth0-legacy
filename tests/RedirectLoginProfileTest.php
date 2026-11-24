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

    private function idToken( array $claims = array() ): string
    {
        return JWT::encode( array_merge( array( 'sub' => self::ID_TOKEN_SUB, 'aud' => 'client-id' ), $claims ), 'secret' );
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
    private function stubHttp( bool $withIdToken, array $profileResponse, array $claims = array() ): void
    {
        $token = array( 'access_token' => self::ACCESS_TOKEN );
        if ( $withIdToken ) {
            $token['id_token'] = $this->idToken( $claims );
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

    public function test_200_without_sub_logs_profile_keys_not_values(): void
    {
        $this->stubHttp( true, $this->response( 200, '{"email":"person@example.gov","name":"Pat Person"}' ) );
        $this->makeManagerForDie = $this->makeManager( 0 );

        list( , , $logged ) = $this->runAndCaptureDie();

        $message = $logged[1][0]['message'];
        $this->assertStringContainsString( 'keys: email,name', $message );
        $this->assertStringNotContainsString( 'person@example.gov', $message );
        $this->assertStringNotContainsString( 'Pat Person', $message );
    }

    public function test_error_body_newlines_are_flattened_in_logs(): void
    {
        $logFile = tempnam( sys_get_temp_dir(), 'a0log' );
        ini_set( 'error_log', $logFile );
        $this->stubHttp( true, $this->response( 429, "x\nwp-auth0 forged line\r\ny", array( 'x-ratelimit-remaining' => array( '0', '1' ) ) ) );
        $this->makeManagerForDie = $this->makeManager( 0 );

        list( , , $logged ) = $this->runAndCaptureDie();

        $contents = file_get_contents( $logFile );
        unlink( $logFile );
        ini_set( 'error_log', '/dev/null' );

        $this->assertStringNotContainsString( "\n", $logged[1][0]['message'] );
        // One fallback line plus one failure line; the body must not add more.
        $this->assertSame( 2, substr_count( trim( $contents ), "\n" ) + 1, 'Body must not add extra log lines.' );
        $this->assertStringContainsString( 'x-ratelimit-remaining=0,1', $contents );
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

    private function runExpectingLoginUser( WP_Auth0_LoginManager $manager ): object
    {
        try {
            $manager->redirect_login();
        } catch ( LoginUserReached $e ) {
            return $e->userinfo;
        }
        $this->fail( 'login_user() was not reached.' );
    }

    private function withLog( callable $fn ): string
    {
        $logFile = tempnam( sys_get_temp_dir(), 'a0log' );
        ini_set( 'error_log', $logFile );
        try {
            $fn();
        } finally {
            $contents = file_get_contents( $logFile );
            unlink( $logFile );
            ini_set( 'error_log', '/dev/null' );
        }
        return $contents;
    }

    public function test_id_token_with_email_skips_management_api_and_builds_profile_from_claims(): void
    {
        $claims = array(
            'email' => 'editor@example.test',
            'email_verified' => true,
            'name' => 'Pat Person',
            'iss' => 'https://example.auth0.com/',
            'exp' => time() + 600,
            'iat' => time(),
            'nonce' => 'abc',
            'at_hash' => 'hash',
            'azp' => 'client-id',
            'sid' => 'session',
            'auth_time' => time(),
            'nbf' => time(),
        );
        Functions\expect( 'wp_remote_post' )->once()->andReturn( $this->response( 200, json_encode( array( 'access_token' => self::ACCESS_TOKEN, 'id_token' => $this->idToken( $claims ) ) ) ) );
        Functions\expect( 'wp_remote_get' )->never();
        $manager = $this->makeManager( 1 );

        $contents = $this->withLog( function () use ( $manager, &$userinfo ) {
            $userinfo = $this->runExpectingLoginUser( $manager );
        } );

        $this->assertSame( self::ID_TOKEN_SUB, $userinfo->user_id );
        $this->assertSame( self::ID_TOKEN_SUB, $userinfo->sub );
        $this->assertSame( 'editor@example.test', $userinfo->email );
        $this->assertSame( 'Pat Person', $userinfo->name );
        $this->assertTrue( $userinfo->email_verified );
        foreach ( array( 'aud', 'iss', 'exp', 'iat', 'nbf', 'nonce', 'at_hash', 'azp', 'sid', 'auth_time' ) as $claim ) {
            $this->assertObjectNotHasProperty( $claim, $userinfo );
        }
        $this->assertStringNotContainsString( 'falling back', $contents );
    }

    public static function emailVerifiedValues(): array
    {
        return array(
            'string true' => array( 'true', true ),
            'int 1' => array( 1, true ),
            'int 0' => array( 0, false ),
            'false' => array( false, false ),
        );
    }

    #[PHPUnit\Framework\Attributes\DataProvider( "emailVerifiedValues" )]
    public function test_email_verified_is_cast_to_bool( $value, bool $expected ): void
    {
        Functions\expect( 'wp_remote_post' )->once()->andReturn( $this->response( 200, json_encode( array( 'access_token' => self::ACCESS_TOKEN, 'id_token' => $this->idToken( array( 'email' => 'editor@example.test', 'email_verified' => $value ) ) ) ) ) );
        Functions\expect( 'wp_remote_get' )->never();

        $userinfo = $this->runExpectingLoginUser( $this->makeManager( 1 ) );

        $this->assertSame( $expected, $userinfo->email_verified );
    }

    public function test_id_token_without_email_falls_back_to_management_api_and_logs(): void
    {
        $this->stubHttp( true, $this->response( 200, json_encode( array( 'user_id' => self::ID_TOKEN_SUB, 'email' => 'editor@example.test', 'email_verified' => true ) ) ), array( 'name' => 'Pat' ) );
        $manager = $this->makeManager( 1 );

        $contents = $this->withLog( function () use ( $manager, &$userinfo ) {
            $userinfo = $this->runExpectingLoginUser( $manager );
        } );

        $this->assertSame( 'editor@example.test', $userinfo->email );
        $this->assertStringContainsString( 'wp-auth0 redirect_login: id_token has no email claim, falling back to Management API', $contents );
        $this->assertStringNotContainsString( 'editor@example.test', $contents );
        $this->assertStringNotContainsString( 'eyJ', $contents );
    }

    public function test_id_token_with_email_but_no_email_verified_falls_back(): void
    {
        $this->stubHttp( true, $this->response( 200, json_encode( array( 'user_id' => self::ID_TOKEN_SUB, 'email' => 'editor@example.test' ) ) ), array( 'email' => 'editor@example.test' ) );

        $this->withLog( function () {
            $this->runExpectingLoginUser( $this->makeManager( 1 ) );
        } );
    }

    public function test_fallback_401_returns_friendly_400(): void
    {
        $this->stubHttp( true, $this->response( 401, '{"statusCode":401,"error":"Unauthorized","message":"Invalid token"}' ), array( 'name' => 'Pat' ) );
        $this->makeManagerForDie = $this->makeManager( 0 );

        $this->assertFriendlyFailure( $this->runAndCaptureDie(), '401' );
    }

    public function test_login_user_with_slim_profile_looks_up_user_by_sub_without_warnings(): void
    {
        $users_repo = Mockery::mock( 'WP_Auth0_UsersRepo' );
        $users_repo->shouldReceive( 'find_auth0_user' )->once()->with( self::ID_TOKEN_SUB )->andThrow( new LoginUserReached( null ) );
        $a0_options = Mockery::mock( 'WP_Auth0_Options' );
        $a0_options->shouldReceive( 'get' )->with( 'requires_verified_email' )->andReturn( 1 );
        $manager = new WP_Auth0_LoginManager( $users_repo, $a0_options );

        $userinfo = (object) array( 'user_id' => self::ID_TOKEN_SUB, 'sub' => self::ID_TOKEN_SUB, 'email' => 'editor@example.test', 'email_verified' => true );

        $this->expectException( LoginUserReached::class );
        $manager->login_user( $userinfo, 'id-token', 'access-token' );
    }

    public function test_edit_profile_and_verify_email_page_tolerate_profile_without_identities(): void
    {
        $profile = (object) array( 'user_id' => self::ID_TOKEN_SUB, 'email' => 'editor@example.test' );
        $current = (object) array( 'auth0_obj' => $profile );
        Functions\when( 'get_currentauth0user' )->justReturn( $current );
        Functions\when( 'add_action' )->justReturn( true );
        Functions\when( 'get_user_meta' )->justReturn( '' );
        Functions\when( 'esc_html_e' )->justReturn( '' );

        $edit = new WP_Auth0_EditProfile( Mockery::mock( 'WP_Auth0_DBManager' ), Mockery::mock( 'WP_Auth0_UsersRepo' ), Mockery::mock( 'WP_Auth0_Options' ) );

        ob_start();
        try {
            $edit->show_change_password();
            $edit->disable_email_field();
        } finally {
            ob_end_clean();
        }
        $this->addToAssertionCount( 1 );
    }

    public function test_lock10_code_flow_requests_profile_and_email_scopes_implicit_unchanged(): void
    {
        foreach ( array( false, true ) as $implicit ) {
            $lock = Mockery::mock( WP_Auth0_Lock10_Options::class )->makePartial()->shouldAllowMockingProtectedMethods();
            $lock->shouldReceive( 'get_auth0_implicit_workflow' )->andReturn( $implicit );
            $lock->shouldReceive( 'get_code_callback_url' )->andReturn( 'https://example.test/index.php?auth0=1' );
            $lock->shouldReceive( 'get_implicit_callback_url' )->andReturn( 'https://example.test/wp-login.php?auth0=1' );
            $lock->shouldReceive( 'get_state_obj' )->andReturn( 'state' );
            $lock->shouldReceive( 'build_settings' )->andReturn( array() );
            $lock->shouldReceive( 'is_registration_enabled' )->andReturn( true );
            $wp_options = Mockery::mock( 'WP_Auth0_Options' );
            $wp_options->shouldReceive( 'get_options' )->andReturn( array() );
            $prop = new ReflectionProperty( WP_Auth0_Lock10_Options::class, 'wp_options' );
            $prop->setValue( $lock, $wp_options );
            $ext = new ReflectionProperty( WP_Auth0_Lock10_Options::class, 'extended_settings' );
            $ext->setValue( $lock, array() );
            $_GET['redirect_to'] = 'https://example.test/';

            $expected = $implicit ? 'openid name email picture nickname email_verified' : 'openid profile email';
            $this->assertSame( $expected, trim( $lock->get_lock_options()['auth']['params']['scope'] ) );
            $this->assertSame( $expected, trim( $lock->get_sso_options()['scope'] ) );
        }
        unset( $_GET['redirect_to'] );
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
