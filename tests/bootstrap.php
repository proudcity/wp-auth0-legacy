<?php

/**
 * PHPUnit bootstrap for auth0.
 *
 * Load order:
 *   1. Composer autoload — loads Patchwork before any plugin files.
 *   2. A spl_autoload_register mapping WP_Auth0_* classes to lib/ and
 *      lib/exceptions/, the same way WP_Auth0::autoloader() does. WP_Auth0.php
 *      itself isn't required: it runs WordPress functions (plugin_dir_path,
 *      etc.) at load time, which aren't available here.
 *
 * Run from the plugin root:
 *   composer install
 *   vendor/bin/phpunit
 */

require_once __DIR__ . '/../vendor/antecedent/patchwork/Patchwork.php';
require_once __DIR__ . '/../vendor/autoload.php';

define( 'ABSPATH', __DIR__ . '/' );
define( 'WPA0_PLUGIN_DIR', dirname( __DIR__ ) . '/' );

spl_autoload_register( function ( $class ) {
    if ( strpos( $class, 'WP_Auth0_' ) !== 0 ) {
        return;
    }

    $paths = array(
        WPA0_PLUGIN_DIR . 'lib/',
        WPA0_PLUGIN_DIR . 'lib/exceptions/',
    );
    $exts = array( '.php', '.class.php' );

    foreach ( $paths as $path ) {
        foreach ( $exts as $ext ) {
            if ( file_exists( $path . $class . $ext ) ) {
                require_once $path . $class . $ext;
                return;
            }
        }
    }
} );
