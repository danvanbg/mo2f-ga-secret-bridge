<?php
/**
 * mo2f-ga-secret-bridge -- fix for Google Authenticator logins broken by
 * "Two-Factor Authentication (2FA) - Passkey & Google Authenticator" (miniOrange) 6.7.0.
 *
 * Bug: up to 6.6.x the on-premise Google Authenticator secret was stored in user meta
 * 'mo2f_gauth_key', AES-128-CBC encrypted with the per-user key in 'mo2f_get_auth_rnd_string'.
 * 6.7.0 reads the secret only from 'mo2f_secret_ga' and has no migration from 'mo2f_gauth_key',
 * so for those users the secret is empty and every code is rejected ("invalid code" /
 * "Too many incorrect attempts"), although the phone app still shows the right codes.
 *
 * Fix: decrypt the old secret exactly as 6.6.x/6.7.0 do (Mo2f_GAuth_AESEncryption::decrypt_data)
 * and store it as 'mo2f_secret_ga'. Plaintext is the legacy format 6.7.0 accepts; it re-saves it
 * encrypted ('enc:...') on the next login. The old meta keys are never changed or deleted.
 * The existing app entry on the phone keeps working; no new QR code is needed.
 *
 * Usage (WP-CLI not required; run as a user that can read wp-config.php):
 *   php mo2f-ga-secret-bridge.php /path/to/wordpress <user_id|--all>            dry run, changes nothing
 *   php mo2f-ga-secret-bridge.php /path/to/wordpress <user_id|--all> --write    write mo2f_secret_ga
 *   php mo2f-ga-secret-bridge.php /path/to/wordpress <user_id> --undo           delete mo2f_secret_ga again
 * --all = every user that has 'mo2f_gauth_key' but no 'mo2f_secret_ga'.
 * The secret itself is never printed.
 *
 * If you are locked out right now: add  define( 'MO2F_DISABLE_2FA_ENFORCEMENT', true );  to
 * wp-config.php (6.7.0 emergency switch), log in, run this script, then remove the line again.
 *
 * Author:  Danail Vankov <danail.vankov@gmail.com>
 * License: MIT
 */

if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

// Same algorithm as Mo2f_GAuth_AESEncryption::decrypt_data (identical in 6.6.0 and 6.7.0).
function mo2f_bridge_decrypt_old( $data, $key ) {
	$c      = base64_decode( (string) $data );
	$cipher = 'AES-128-CBC';
	$ivlen  = openssl_cipher_iv_length( $cipher );
	$iv     = substr( $c, 0, $ivlen );
	$raw    = substr( $c, $ivlen + 32 );
	return openssl_decrypt( $raw, $cipher, (string) $key, OPENSSL_RAW_DATA, $iv );
}

function mo2f_bridge_is_base32( $s ) {
	return is_string( $s ) && 1 === preg_match( '/^[A-Z2-7]{16,64}$/', strtoupper( $s ) );
}

/** Process one user. Returns 0 on success / nothing to do, >0 on a stop condition. */
function mo2f_bridge_user( $user_id, $mode ) {
	$old_enc = (string) get_user_meta( $user_id, 'mo2f_gauth_key', true );
	$old_key = (string) get_user_meta( $user_id, 'mo2f_get_auth_rnd_string', true );
	$current = (string) get_user_meta( $user_id, 'mo2f_secret_ga', true );
	echo "user $user_id: mo2f_gauth_key len=" . strlen( $old_enc ) . ', mo2f_get_auth_rnd_string len=' . strlen( $old_key ) . ', mo2f_secret_ga len=' . strlen( $current ) . "\n";

	if ( '--undo' === $mode ) {
		$ok = delete_user_meta( $user_id, 'mo2f_secret_ga' );
		echo '  undo: ' . ( $ok ? 'mo2f_secret_ga deleted' : 'nothing to delete' ) . "\n";
		return 0;
	}
	if ( '' === $old_enc || '' === $old_key ) {
		echo "  skip: no 6.6.x secret for this user\n";
		return 3;
	}
	if ( '' !== $current ) {
		echo "  skip: mo2f_secret_ga already set, nothing written\n";
		return 0;
	}
	$plain = mo2f_bridge_decrypt_old( $old_enc, $old_key );
	if ( ! mo2f_bridge_is_base32( $plain ) ) {
		echo '  STOP: old secret does not decrypt to a valid Base32 secret (len=' . strlen( (string) $plain ) . "), nothing written\n";
		return 4;
	}
	if ( '--write' !== $mode ) {
		echo '  dry run OK: --write would set mo2f_secret_ga (len ' . strlen( $plain ) . ")\n";
		return 0;
	}
	update_user_meta( $user_id, 'mo2f_secret_ga', strtoupper( $plain ) );
	$check = (string) get_user_meta( $user_id, 'mo2f_secret_ga', true );
	$ok    = ( strtoupper( $plain ) === $check );
	echo '  write: mo2f_secret_ga len=' . strlen( $check ) . ' -> ' . ( $ok ? 'OK' : 'FAILED' ) . "\n";
	return $ok ? 0 : 6;
}

if ( getenv( 'MO2F_BRIDGE_SELFTEST' ) ) {
	return; // Test harness includes the file only for the functions above.
}

$wp_path = isset( $argv[1] ) ? rtrim( $argv[1], '/' ) : '';
$target  = isset( $argv[2] ) ? $argv[2] : '';
$mode    = isset( $argv[3] ) ? $argv[3] : '--dry-run';
if ( '' === $wp_path || ! is_file( $wp_path . '/wp-load.php' ) || '' === $target
	|| ! in_array( $mode, array( '--dry-run', '--write', '--undo' ), true )
	|| ( '--all' === $target && '--undo' === $mode )
	|| ( '--all' !== $target && (int) $target <= 0 ) ) {
	fwrite( STDERR, "usage: php mo2f-ga-secret-bridge.php /path/to/wordpress <user_id|--all> [--write|--undo]\n" );
	exit( 2 );
}

if ( empty( $_SERVER['HTTP_HOST'] ) ) {
	$_SERVER['HTTP_HOST'] = 'localhost';
}
if ( empty( $_SERVER['REQUEST_URI'] ) ) {
	$_SERVER['REQUEST_URI'] = '/';
}
define( 'WP_USE_THEMES', false );
require $wp_path . '/wp-load.php';

if ( '--all' === $target ) {
	global $wpdb;
	$ids = $wpdb->get_col(
		"SELECT DISTINCT o.user_id FROM {$wpdb->usermeta} o
		 LEFT JOIN {$wpdb->usermeta} n ON n.user_id = o.user_id AND n.meta_key = 'mo2f_secret_ga'
		 WHERE o.meta_key = 'mo2f_gauth_key' AND o.meta_value <> '' AND ( n.meta_value IS NULL OR n.meta_value = '' )"
	);
	echo 'users with only the 6.6.x secret: ' . count( $ids ) . "\n";
	$rc = 0;
	foreach ( $ids as $id ) {
		$rc = max( $rc, mo2f_bridge_user( (int) $id, $mode ) );
	}
	exit( $rc );
}
exit( mo2f_bridge_user( (int) $target, $mode ) );
