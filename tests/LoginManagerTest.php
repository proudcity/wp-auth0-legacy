<?php

use Brain\Monkey;
use Brain\Monkey\Filters;
use Brain\Monkey\Functions;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;

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

        Monkey\tearDown();
        parent::tearDown();
    }

    private function makeLoginManager(): WP_Auth0_LoginManager
    {
        $users_repo = Mockery::mock( 'WP_Auth0_UsersRepo' );
        $a0_options = Mockery::mock( 'WP_Auth0_Options' );
        $a0_options->shouldReceive( 'get' )->with( 'sso' )->andReturn( 1 );

        return new WP_Auth0_LoginManager( $users_repo, $a0_options );
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
        Functions\expect( 'wp_die' )->once()->andReturnUsing( function ( $msg ) use ( &$captured ) {
            $captured = $msg;
        } );

        $manager = $this->makeLoginManager();
        $manager->init_auth0();

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
