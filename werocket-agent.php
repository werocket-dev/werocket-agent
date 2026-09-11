<?php
use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

/**
 * Plugin Name: WeRocket Agent
 * Plugin URI: https://werocket.com
 * Description: Agent sécurisé pour l'audit de maintenance et les mises à jour à distance ! Authentification par signature Ed25519 (clé publique) — plus de secret partagé.
 * Version: 3.0.0
 * Author: Romain
 * License: GPL v2 or later
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

// Clé publique de production — n'est PAS un secret : sa fuite ne permet pas de forger une
// signature, seulement de la vérifier. La clé privée correspondante ne vit que sur le backend.
define( 'WEROCKET_PUBLIC_KEY_HEX', 'a75d86c991623949b9201d3df9fcce99073982fe76cd24d829032bd78e02cdbc' );

class WeRocket_Agent {

    private $public_key;
    private $header_key;
    private $namespace = 'werocket/v1';
    private $max_attempts = 5;
    private $time_window = 3600;
    private $timestamp_tolerance = 300;

    public function __construct() {
        if ( ! defined( 'WEROCKET_PUBLIC_KEY_HEX' ) || empty( WEROCKET_PUBLIC_KEY_HEX ) ) {
            if ( is_admin() ) {
                add_action( 'admin_notices', array( $this, 'admin_notice' ) );
            }
            return;
        }

        if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
            if ( is_admin() ) {
                add_action( 'admin_notices', array( $this, 'admin_notice_sodium' ) );
            }
            return;
        }

        $this->public_key = hex2bin( WEROCKET_PUBLIC_KEY_HEX );
        $this->header_key = defined( 'WEROCKET_AGENT_HEADER_KEY' ) ? WEROCKET_AGENT_HEADER_KEY : '';

        add_action( 'rest_api_init', array( $this, 'register_api_routes' ) );
    }

    public function admin_notice() {
        echo '<div class="notice notice-error"><p><strong>WeRocket Agent:</strong> Clé publique manquante (WEROCKET_PUBLIC_KEY_HEX).</p></div>';
    }

    public function admin_notice_sodium() {
        echo '<div class="notice notice-error"><p><strong>WeRocket Agent:</strong> Extension PHP <code>sodium</code> manquante (PHP ≥ 7.2 requis).</p></div>';
    }

    public function register_api_routes() {
        // 1. Route pour le statut (Lecture)
        register_rest_route(
            $this->namespace,
            '/status',
            array(
                'methods'             => 'POST',
                'callback'            => array( $this, 'handle_status_request' ),
                'permission_callback' => '__return_true',
                'args'                => $this->get_default_args(),
            )
        );

        // 2. Route pour mettre à jour un plugin précis (Action)
        register_rest_route(
            $this->namespace,
            '/update-plugin',
            array(
                'methods'             => 'POST',
                'callback'            => array( $this, 'handle_update_plugin_request' ),
                'permission_callback' => '__return_true',
                'args'                => array_merge( $this->get_default_args(), array(
                    'plugin_path' => array(
                        'required' => false,
                        'type' => 'string',
                        'sanitize_callback' => 'sanitize_text_field'
                    ),
                    'plugin_slug' => array(
                        'required' => false,
                        'type' => 'string',
                        'sanitize_callback' => 'sanitize_text_field'
                    ),
                )),
            )
        );

        // 3. Route pour mettre à jour le core WordPress (Action)
        register_rest_route(
            $this->namespace,
            '/update-core',
            array(
                'methods'             => 'POST',
                'callback'            => array( $this, 'handle_update_core_request' ),
                'permission_callback' => '__return_true',
                'args'                => $this->get_default_args(),
            )
        );

        // 4. Configuration de la liste blanche d'IP autorisées à appeler l'API
        register_rest_route(
            $this->namespace,
            '/set-allowed-ips',
            array(
                'methods'             => 'POST',
                'callback'            => array( $this, 'handle_set_allowed_ips_request' ),
                'permission_callback' => '__return_true',
                'args'                => array_merge( $this->get_default_args(), array(
                    'ips' => array(
                        'required'          => true,
                        'type'              => 'string', // Liste d'IP séparées par des virgules
                        'sanitize_callback' => 'sanitize_text_field',
                    ),
                )),
            )
        );
    }

    // Plus de paramètre "token" : la signature Ed25519 est la seule preuve d'identité nécessaire.
    private function get_default_args() {
        return array(
            'timestamp' => array( 'required' => true, 'type' => 'integer', 'sanitize_callback' => 'absint' ),
            'signature' => array( 'required' => true, 'type' => 'string', 'sanitize_callback' => 'sanitize_text_field' ),
        );
    }

    // --- SÉCURITÉ CENTRALISÉE ---

    // IP allowlist appliquée à TOUTES les routes (pas seulement les routes sensibles).
    private function authenticate_request( WP_REST_Request $request ) {
        if ( ! $this->verify_ip_allowlist() ) {
            $this->log_event( 'ip_not_allowed', $this->get_client_ip() );
            return new WP_Error( 'ip_not_allowed', 'IP non autorisée pour cette route', array( 'status' => 403 ) );
        }
        if ( ! $this->check_rate_limit() ) return new WP_Error( 'rate_limit', 'Trop de requêtes', array( 'status' => 429 ) );
        if ( ! $this->verify_header() ) return new WP_Error( 'header_invalid', 'Header invalide', array( 'status' => 403 ) );

        $timestamp = $request->get_param( 'timestamp' );
        $signature = $request->get_param( 'signature' );

        if ( ! $this->verify_timestamp( $timestamp ) ) return new WP_Error( 'timestamp_old', 'Timestamp expiré', array( 'status' => 403 ) );
        if ( ! $this->verify_signature( $signature, $timestamp, $request->get_route() ) ) return new WP_Error( 'sig_invalid', 'Signature invalide', array( 'status' => 403 ) );

        $ip_address = $this->get_client_ip();
        delete_transient( 'werocket_rate_limit_' . md5( $ip_address ) );
        $this->log_event( 'access_granted', $ip_address );
        return true;
    }

    private function check_rate_limit() {
        $ip_address = $this->get_client_ip();
        $transient_key = 'werocket_rate_limit_' . md5( $ip_address );
        $attempts = get_transient( $transient_key );
        if ( false === $attempts ) { $attempts = 0; }

        if ( $attempts >= $this->max_attempts ) {
            $this->log_event( 'rate_limit', $ip_address );
            return false;
        }

        set_transient( $transient_key, $attempts + 1, $this->time_window );
        return true;
    }

    // L'IP de connexion réelle (REMOTE_ADDR) ne peut pas être falsifiée par le client, contrairement
    // aux headers X-Forwarded-For / X-Real-IP / CF-Connecting-IP qu'il envoie lui-même. On ne fait
    // confiance à ces headers que si la requête vient d'un proxy explicitement déclaré de confiance
    // (WEROCKET_TRUSTED_PROXIES dans wp-config), sinon on s'appuie uniquement sur REMOTE_ADDR.
    private function get_client_ip() {
        $remote_addr = ( isset( $_SERVER['REMOTE_ADDR'] ) && filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP ) )
            ? $_SERVER['REMOTE_ADDR']
            : '0.0.0.0';

        if ( $this->is_trusted_proxy( $remote_addr ) ) {
            if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && filter_var( trim( $_SERVER['HTTP_CF_CONNECTING_IP'] ), FILTER_VALIDATE_IP ) ) {
                return trim( $_SERVER['HTTP_CF_CONNECTING_IP'] );
            }
            if ( isset( $_SERVER['HTTP_X_REAL_IP'] ) && filter_var( trim( $_SERVER['HTTP_X_REAL_IP'] ), FILTER_VALIDATE_IP ) ) {
                return trim( $_SERVER['HTTP_X_REAL_IP'] );
            }
            if ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
                $chain = array_map( 'trim', explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
                $last = end( $chain );
                if ( filter_var( $last, FILTER_VALIDATE_IP ) ) return $last;
            }
        }

        return $remote_addr;
    }

    private function is_trusted_proxy( $remote_addr ) {
        if ( ! defined( 'WEROCKET_TRUSTED_PROXIES' ) || empty( WEROCKET_TRUSTED_PROXIES ) ) return false;
        $trusted = array_filter( array_map( 'trim', explode( ',', WEROCKET_TRUSTED_PROXIES ) ) );
        return in_array( $remote_addr, $trusted, true );
    }

    // Liste blanche d'IP autorisées à appeler l'API. Configurable à distance via /set-allowed-ips
    // (stockée en wp_options), avec WEROCKET_ALLOWED_IPS (wp-config) comme repli.
    // Vide des deux côtés = pas de restriction (bootstrap avant première configuration).
    private function get_allowed_ips() {
        $stored = get_option( 'werocket_allowed_ips', '' );
        $raw = ! empty( $stored ) ? $stored : ( defined( 'WEROCKET_ALLOWED_IPS' ) ? WEROCKET_ALLOWED_IPS : '' );
        if ( empty( $raw ) ) return array();
        return array_filter( array_map( 'trim', explode( ',', $raw ) ) );
    }

    private function verify_ip_allowlist() {
        $allowed = $this->get_allowed_ips();
        if ( empty( $allowed ) ) return true; // Pas encore configurée : pas de restriction.
        return in_array( $this->get_client_ip(), $allowed, true );
    }

    private function verify_header() {
        if ( empty( $this->header_key ) ) return true;
        $provided = isset( $_SERVER['HTTP_X_WEROCKET_KEY'] ) ? $_SERVER['HTTP_X_WEROCKET_KEY'] : '';
        $valid = hash_equals( $this->header_key, $provided );
        if ( ! $valid ) {
            $this->log_event( 'header_invalid', $this->get_client_ip() );
        }
        return $valid;
    }

    private function verify_timestamp( $timestamp ) {
        if ( empty( $timestamp ) || ! is_numeric( $timestamp ) ) return false;
        $diff = abs( time() - $timestamp );
        return $diff <= $this->timestamp_tolerance;
    }

    // Vérifie une signature Ed25519 détachée avec la clé PUBLIQUE (la clé privée ne quitte
    // jamais le backend). Message signé : "site_url|timestamp|route" (deux variantes testées
    // pour tolérer la présence/absence du slash final sur l'URL du site).
    private function verify_signature( $provided_signature_hex, $timestamp, $route ) {
        if ( ! ctype_xdigit( $provided_signature_hex ) || strlen( $provided_signature_hex ) !== 128 ) {
            return false; // signature détachée Ed25519 = 64 octets = 128 caractères hex
        }
        $signature = hex2bin( $provided_signature_hex );

        $site_url = get_site_url();
        $site_url_clean = rtrim( $site_url, '/' );

        $message1 = $site_url . '|' . $timestamp . '|' . $route;
        $message2 = $site_url_clean . '|' . $timestamp . '|' . $route;

        return sodium_crypto_sign_verify_detached( $signature, $message1, $this->public_key )
            || sodium_crypto_sign_verify_detached( $signature, $message2, $this->public_key );
    }

    private function log_event( $type, $ip ) {
        error_log( sprintf( '[WeRocket Security] %s | IP: %s | Site: %s', $type, $ip, get_site_url() ) );
    }

    // --- HANDLERS D'API ---

    // 1. L'Audit
    public function handle_status_request( WP_REST_Request $request ) {
        $auth = $this->authenticate_request( $request );
        if ( is_wp_error( $auth ) ) return $auth;

        return rest_ensure_response( array(
            'success'   => true,
            'timestamp' => time(),
            'site'      => array( 'url'  => get_site_url(), 'name' => get_bloginfo( 'name' ) ),
            'versions'  => $this->get_versions_info(),
            'plugins'   => $this->get_plugins_info(),
            'theme'     => $this->get_theme_info(),
            'server'    => $this->get_server_info(),
        ));
    }

    // 2. La mise à jour d'un plugin à distance
    public function handle_update_plugin_request( WP_REST_Request $request ) {
        $auth = $this->authenticate_request( $request );
        if ( is_wp_error( $auth ) ) return $auth;

        $plugin_path = $request->get_param( 'plugin_path' ); // ex: "seo-by-rank-math/rank-math.php"
        $plugin_slug = $request->get_param( 'plugin_slug' );

        if ( empty( $plugin_path ) && ! empty( $plugin_slug ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
            foreach ( get_plugins() as $path => $info ) {
                if ( strpos( $path, $plugin_slug . '/' ) === 0 ) {
                    $plugin_path = $path;
                    break;
                }
            }
        }

        if ( empty( $plugin_path ) ) {
            return new WP_Error( 'plugin_not_found', "Plugin '$plugin_slug' introuvable.", array( 'status' => 404 ) );
        }

        // Chargement forcé des fichiers d'administration de WordPress
        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/class-automatic-upgrader-skin.php';
        require_once ABSPATH . 'wp-admin/includes/plugin.php';

        // Initialisation du système de fichiers WP
        WP_Filesystem();

        // Validation stricte du format : dossier/fichier.php, sans traversal
        if ( ! preg_match( '#^[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+\.php$#', $plugin_path ) ) {
            return new WP_Error( 'plugin_path_invalid', 'Chemin de plugin invalide.', array( 'status' => 400 ) );
        }

        // On vérifie que le plugin existe bien
        if ( ! file_exists( WP_PLUGIN_DIR . '/' . $plugin_path ) ) {
            return new WP_Error( 'plugin_not_found', 'Le plugin spécifié est introuvable.', array( 'status' => 404 ) );
        }

        // On vérifie s'il était actif avant la mise à jour
        $was_active = is_plugin_active( $plugin_path );

        // Lancement de la mise à jour silencieuse
        $skin     = new Automatic_Upgrader_Skin();
        $upgrader = new Plugin_Upgrader( $skin );
        $result   = $upgrader->upgrade( $plugin_path );

        // Analyse du résultat
        if ( is_wp_error( $result ) ) {
            return new WP_Error( 'upgrade_failed', $result->get_error_message(), array( 'status' => 500 ) );
        }

        if ( null === $result ) {
            return rest_ensure_response( array( 'success' => true, 'message' => 'Déjà à jour', 'plugin' => $plugin_path ) );
        }

        if ( false === $result ) {
            return new WP_Error( 'upgrade_failed', 'La mise à jour a échoué silencieusement.', array( 'status' => 500 ) );
        }

        // Réactivation si nécessaire (parfois WP désactive le plugin pendant l'update)
        if ( $was_active && ! is_plugin_active( $plugin_path ) ) {
            activate_plugin( $plugin_path );
        }

        return rest_ensure_response( array(
            'success' => true,
            'message' => 'Mise à jour réussie',
            'plugin'  => $plugin_path
        ));
    }

    // 3. La mise à jour du core WordPress
    public function handle_update_core_request( WP_REST_Request $request ) {
        $auth = $this->authenticate_request( $request );
        if ( is_wp_error( $auth ) ) return $auth;

        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        require_once ABSPATH . 'wp-admin/includes/update.php';
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/class-core-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/class-automatic-upgrader-skin.php';

        WP_Filesystem();

        // Force la vérification officielle WordPress.org avant de lire les updates
        wp_version_check( array(), true );
        $updates = get_core_updates();

        if ( empty( $updates ) || ! isset( $updates[0]->response ) || 'upgrade' !== $updates[0]->response ) {
            return rest_ensure_response( array(
                'success' => true,
                'message' => 'WordPress déjà à jour',
                'version' => get_bloginfo( 'version' ),
            ));
        }

        $skin     = new Automatic_Upgrader_Skin();
        $upgrader = new Core_Upgrader( $skin );
        $result   = $upgrader->upgrade( $updates[0] );

        if ( is_wp_error( $result ) ) {
            return new WP_Error( 'core_upgrade_failed', $result->get_error_message(), array( 'status' => 500 ) );
        }

        if ( false === $result ) {
            return new WP_Error( 'core_upgrade_failed', 'La mise à jour du core a échoué silencieusement.', array( 'status' => 500 ) );
        }

        return rest_ensure_response( array(
            'success' => true,
            'message' => 'WordPress mis à jour',
            'version' => get_bloginfo( 'version' ),
        ));
    }

    // 4. Configuration de la liste blanche d'IP
    public function handle_set_allowed_ips_request( WP_REST_Request $request ) {
        $auth = $this->authenticate_request( $request );
        if ( is_wp_error( $auth ) ) return $auth;

        $ips_raw = $request->get_param( 'ips' );
        $ips = array_filter( array_map( 'trim', explode( ',', $ips_raw ) ) );

        foreach ( $ips as $ip ) {
            if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                return new WP_Error( 'ip_invalid', sprintf( "L'adresse IP '%s' est invalide.", $ip ), array( 'status' => 400 ) );
            }
        }

        update_option( 'werocket_allowed_ips', implode( ',', $ips ) );
        $this->log_event( 'allowed_ips_updated', $this->get_client_ip() );

        return rest_ensure_response( array(
            'success' => true,
            'message' => 'Liste blanche IP mise à jour',
            'ips'     => array_values( $ips ),
        ));
    }

    // --- DATA GETTERS ---

    private function get_versions_info() {
        global $wp_version, $wpdb;
        return array( 'wordpress' => $wp_version, 'php' => PHP_VERSION, 'mysql' => $wpdb->db_version() );
    }

    private function get_plugins_info() {
        if ( ! function_exists( 'get_plugins' ) ) { require_once ABSPATH . 'wp-admin/includes/plugin.php'; }
        $all_plugins = get_plugins();
        $active_plugins = get_option( 'active_plugins', array() );
        $data = array();

        foreach ( $all_plugins as $path => $info ) {
            $plugin_slug = dirname( $path );
            if ( '.' === $plugin_slug ) { $plugin_slug = basename( $path, '.php' ); }

            $data[] = array(
                'name' => $info['Name'],
                'version' => $info['Version'],
                'slug' => $plugin_slug,
                'path' => $path, // AJOUT IMPORTANT : on renvoie le chemin complet pour pouvoir cibler la mise à jour plus tard
                'author' => isset($info['Author']) ? $info['Author'] : '',
                'is_active' => in_array( $path, $active_plugins, true ),
                'update_available' => $this->check_update( $path )
            );
        }
        return $data;
    }

    private function check_update( $path ) {
        $updates = get_site_transient( 'update_plugins' );
        if ( isset( $updates->response[ $path ] ) ) {
            return array( 'available' => true, 'new_version' => $updates->response[ $path ]->new_version );
        }
        return array( 'available' => false );
    }

    private function get_theme_info() {
        $theme = wp_get_theme();
        return array(
            'name' => $theme->get('Name'),
            'version' => $theme->get('Version'),
            'author' => $theme->get('Author')
        );
    }

    private function get_server_info() {
        return array(
            'software' => isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( $_SERVER['SERVER_SOFTWARE'] ) : 'Unknown',
            'php_memory' => ini_get( 'memory_limit' ),
            'wp_memory' => WP_MEMORY_LIMIT,
            'upload_max' => ini_get( 'upload_max_filesize' ),
            'post_max' => ini_get( 'post_max_size' )
        );
    }
}

// Init & Activation
add_action( 'plugins_loaded', function() { new WeRocket_Agent(); } );

register_activation_hook( __FILE__, function() {
    flush_rewrite_rules();
});

register_deactivation_hook( __FILE__, function() {
    global $wpdb;
    $wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_werocket_rate_limit_%'" );
    $wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_werocket_rate_limit_%'" );
    flush_rewrite_rules();
});

// ============================================================================
// SYSTÈME DE MISE À JOUR PRIVÉ (GitHub via Plugin Update Checker)
// ============================================================================

require_once __DIR__ . '/lib/plugin-update-checker/plugin-update-checker.php';

$myUpdateChecker = PucFactory::buildUpdateChecker(
    'https://github.com/werocket-dev/werocket-agent',
    __FILE__,
    'werocket-agent'
);

if ( defined( 'WEROCKET_GITHUB_TOKEN' ) && ! empty( WEROCKET_GITHUB_TOKEN ) ) {
    $myUpdateChecker->setAuthentication( WEROCKET_GITHUB_TOKEN );
}

$myUpdateChecker->getVcsApi()->enableReleaseAssets();

if ( defined( 'WEROCKET_BETA_TESTER' ) && WEROCKET_BETA_TESTER ) {
    $myUpdateChecker->setBranch( 'main' );
}

add_filter( 'auto_update_plugin', function ( $update, $item ) {
    if ( isset( $item->slug ) && 'werocket-agent' === $item->slug ) {
        return true;
    }
    return $update;
}, 10, 2 );
