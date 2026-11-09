<?php

use Brain\Monkey;
use Brain\Monkey\Filters;
use Brain\Monkey\Functions;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;

require_once WPA0_PLUGIN_DIR . 'lib/php-jwt/Authentication/JWT.php';

/**
 * Tests for WP_Auth0_LoginManager (#2962).
 *
 * Bug 1: the silent SSO handler (login_message filter + auth0-sso-handler-lock10.php
 * template) POSTs an empty token to /?auth0=implicit, which throws
 * "Wrong number of segments". The fix removes the filter, the method and the
 * template entirely.
 *
 * Bug 2: the "<- Login" links on the error and verify-email pages use bare
 * wp_login_url(), which the tenant .htaccess BLOCK_LOGIN rule returns 403 for.
 * The fix carries redirect_to through wp_login_url( admin_url() ).
 */
class LoginManagerTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();
    }

    protected function tearDown(): void
    {
        unset( $_REQUEST['auth0'], $_REQUEST['error_description'], $_REQUEST['error'] );
        $GLOBALS['wp_query'] = null;
        $_POST = array();
        unset( $_SERVER['REQUEST_METHOD'] );

        Monkey\tearDown();
        parent::tearDown();
    }

    private function makeLoginManager( $implicit = false ): WP_Auth0_LoginManager
    {
        $users_repo = Mockery::mock( 'WP_Auth0_UsersRepo' );
        $a0_options = Mockery::mock( 'WP_Auth0_Options' );
        $a0_options->shouldReceive( 'get' )->with( 'sso' )->andReturn( 1 );
        $a0_options->shouldReceive( 'get' )->with( 'auth0_implicit_workflow' )->andReturn( $implicit );
        $a0_options->shouldReceive( 'get_client_secret_as_key' )->andReturn( 'secret' );
        $a0_options->shouldReceive( 'get_client_signing_algorithm' )->andReturn( 'HS256' );

        return new WP_Auth0_LoginManager( $users_repo, $a0_options );
    }

    private function stubDieDeps(): void
    {
        Functions\when( 'admin_url' )->justReturn( 'https://example.test/wp-admin/' );
        Functions\when( 'wp_login_url' )->justReturn( 'https://example.test/wp-login.php' );
        Functions\stubEscapeFunctions();
        Functions\stubTranslationFunctions();
    }

    private function runImplicit( WP_Auth0_LoginManager $manager, int $code ): void
    {
        $_REQUEST['auth0'] = 'implicit';
        $GLOBALS['wp_query'] = null;
        $this->stubDieDeps();

        Functions\expect( 'wp_die' )->once()->with( Mockery::any(), '', array( 'response' => $code ) );

        $manager->init_auth0();
    }

    public function test_implicit_off_bare_get_returns_400_without_log_write(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        Functions\expect( 'update_option' )->never();

        $this->runImplicit( $this->makeLoginManager( false ), 400 );
    }

    public function test_implicit_off_post_token_returns_400_without_log_write(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST['token'] = 'abc';
        Functions\expect( 'update_option' )->never();

        $this->runImplicit( $this->makeLoginManager( false ), 400 );
    }

    public function test_implicit_on_get_returns_400_without_log_write(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        Functions\expect( 'update_option' )->never();

        $this->runImplicit( $this->makeLoginManager( true ), 400 );
    }

    public function test_implicit_on_missing_token_returns_400_without_log_write(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        Functions\expect( 'update_option' )->never();

        $this->runImplicit( $this->makeLoginManager( true ), 400 );
    }

    public function test_implicit_on_empty_token_returns_400_without_log_write(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST['token'] = '';
        Functions\expect( 'update_option' )->never();

        $this->runImplicit( $this->makeLoginManager( true ), 400 );
    }

    public function test_implicit_on_array_token_returns_400_without_log_write(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST['token'] = array( 'x' );
        Functions\expect( 'update_option' )->never();

        $this->runImplicit( $this->makeLoginManager( true ), 400 );
    }

    public function test_implicit_on_junk_token_returns_400_with_one_log_write(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST['token'] = 'abc';
        Functions\when( 'get_option' )->justReturn( array() );
        ini_set( 'error_log', '/dev/null' );
        Functions\expect( 'update_option' )->once();

        $this->runImplicit( $this->makeLoginManager( true ), 400 );
    }

    public function test_before_login_exception_returns_403(): void
    {
        $_REQUEST['auth0'] = '1';
        $GLOBALS['wp_query'] = null;
        $this->stubDieDeps();
        Functions\when( 'wp_logout_url' )->justReturn( 'https://example.test/logout' );

        $manager = Mockery::mock( WP_Auth0_LoginManager::class, array( Mockery::mock( 'WP_Auth0_UsersRepo' ), Mockery::mock( 'WP_Auth0_Options' ) ) )->makePartial();
        $manager->shouldReceive( 'redirect_login' )->andThrow( new WP_Auth0_BeforeLoginException( 'nope' ) );

        Functions\expect( 'wp_die' )->once()->with( Mockery::any(), '', array( 'response' => 403 ) );

        $manager->init_auth0();
    }

    public function test_throwable_from_redirect_login_returns_400(): void
    {
        $_REQUEST['auth0'] = '1';
        $GLOBALS['wp_query'] = null;
        $this->stubDieDeps();
        ini_set( 'error_log', '/dev/null' );

        $manager = Mockery::mock( WP_Auth0_LoginManager::class, array( Mockery::mock( 'WP_Auth0_UsersRepo' ), Mockery::mock( 'WP_Auth0_Options' ) ) )->makePartial();
        $manager->shouldReceive( 'redirect_login' )->andThrow( new \TypeError( 'boom' ) );

        $captured = null;
        Functions\expect( 'wp_die' )->once()->andReturnUsing( function ( $msg, $title, $args ) use ( &$captured ) {
            $captured = array( $msg, $args );
        } );

        $manager->init_auth0();

        $this->assertSame( array( 'response' => 400 ), $captured[1] );
        $this->assertStringNotContainsString( 'boom', $captured[0] );
    }

    public function test_init_does_not_register_sso_login_message_filter(): void
    {
        Filters\expectAdded( 'login_message' )->never();

        $manager = $this->makeLoginManager();
        $manager->init();
    }

    public function test_sso_handler_removed(): void
    {
        $this->assertFileDoesNotExist(
            WPA0_PLUGIN_DIR . 'templates/auth0-sso-handler-lock10.php',
            'The silent SSO handler template must be deleted.'
        );
        $this->assertFalse(
            method_exists( WP_Auth0_LoginManager::class, 'auth0_sso_footer' ),
            'auth0_sso_footer() must be removed.'
        );
    }

    public function test_login_error_link_carries_redirect_to(): void
    {
        $_REQUEST['auth0'] = '1';
        $_REQUEST['error_description'] = '<script>alert(1)</script>';
        $GLOBALS['wp_query'] = null;

        Functions\when( 'admin_url' )->justReturn( 'https://example.test/wp-admin/' );
        Functions\when( 'wp_login_url' )->alias( function ( $redirect = '' ) {
            $url = 'https://example.test/wp-login.php';
            if ( ! empty( $redirect ) ) {
                $url .= '?redirect_to=' . rawurlencode( $redirect );
            }
            return $url;
        } );
        Functions\stubEscapeFunctions();
        Functions\stubTranslationFunctions();

        $captured = null;
        $response = null;
        Functions\expect( 'wp_die' )->once()->andReturnUsing( function ( $msg, $title = '', $args = array() ) use ( &$captured, &$response ) {
            $captured = $msg;
            $response = $args['response'] ?? null;
        } );

        $manager = $this->makeLoginManager();
        $manager->init_auth0();

        $this->assertSame( 400, $response );

        $this->assertStringContainsString( 'redirect_to=', $captured );
        $this->assertStringNotContainsString( 'href="https://example.test/wp-login.php"', $captured );
        $this->assertStringContainsString( '&lt;script&gt;', $captured );
        $this->assertStringNotContainsString( '<script>alert(1)</script>', $captured );
    }

    public function test_verify_email_link_carries_redirect_to(): void
    {
        Functions\when( 'admin_url' )->justReturn( 'https://example.test/wp-admin/' );
        Functions\when( 'wp_login_url' )->alias( function ( $redirect = '' ) {
            $url = 'https://example.test/wp-login.php';
            if ( ! empty( $redirect ) ) {
                $url .= '?redirect_to=' . rawurlencode( $redirect );
            }
            return $url;
        } );
        Functions\stubEscapeFunctions();
        Functions\stubTranslationFunctions();

        $domain = 'example.auth0.com';
        $userId = 'auth0|123';
        $token = 'token-value';
        $email = 'user@example.test';

        ob_start();
        include WPA0_PLUGIN_DIR . 'templates/verify-email.php';
        $output = ob_get_clean();

        $this->assertMatchesRegularExpression(
            '/<a[^>]+href="[^"]*redirect_to=[^"]*"[^>]*>\s*(?:&larr;|←)\s*Login/u',
            $output
        );
    }
}
