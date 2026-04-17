<?php
use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

/**
 * Plugin Name: WeRocket Agent
 * Plugin URI: https://werocket.com
 * Description: Agent sécurisé pour l'audit de maintenance et les mises à jour à distance !
 * Version: 2.6.0
 * Author: Romain
 * License: GPL v2 or later
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

class WeRocket_Agent {
    
    private $security_token;
    private $header_key;
    private $namespace = 'werocket/v1';
    private $max_attempts = 5;
    private $time_window = 3600;
    private $timestamp_tolerance = 300;
    
    public function __construct() {
        // Vérification TOKEN
        if ( ! defined( 'WEROCKET_AGENT_TOKEN' ) || empty( WEROCKET_AGENT_TOKEN ) ) {
            if ( is_admin() ) {
                add_action( 'admin_notices', array( $this, 'admin_notice' ) );
            }
            return;
        }
        
        $this->security_token = WEROCKET_AGENT_TOKEN;
        $this->header_key = defined('WEROCKET_AGENT_HEADER_KEY') ? WEROCKET_AGENT_HEADER_KEY : '';

        add_action( 'rest_api_init', array( $this, 'register_api_routes' ) );
    }
    
    public function admin_notice() {
        echo '<div class="notice notice-error"><p><strong>WeRocket Agent:</strong> Ajoutez <code>define(\'WEROCKET_AGENT_TOKEN\', \'...\');</code> dans wp-config.php</p></div>';
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

        // 2. NOUVELLE Route pour mettre à jour un plugin précis (Action)
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
    }

    // Arguments de sécurité par défaut pour toutes nos routes
    private function get_default_args() {
        return array(
            'token'     => array('required' => true, 'type' => 'string', 'sanitize_callback' => 'sanitize_text_field'),
            'timestamp' => array('required' => true, 'type' => 'integer', 'sanitize_callback' => 'absint'),
            'signature' => array('required' => true, 'type' => 'string', 'sanitize_callback' => 'sanitize_text_field'),
        );
    }

    // --- SÉCURITÉ CENTRALISÉE ---

    // Cette fonction vérifie tout. Si c'est bon elle retourne true, sinon une erreur WP_Error.
    private function authenticate_request( WP_REST_Request $request ) {
        if ( ! $this->check_rate_limit() ) return new WP_Error( 'rate_limit', 'Trop de requêtes', array( 'status' => 429 ) );
        if ( ! $this->verify_header() ) return new WP_Error( 'header_invalid', 'Header invalide', array( 'status' => 403 ) );
        
        $token = $request->get_param( 'token' );
        $timestamp = $request->get_param( 'timestamp' );
        $signature = $request->get_param( 'signature' );
        
        if ( ! $this->verify_token( $token ) ) return new WP_Error( 'token_invalid', 'Token invalide', array( 'status' => 403 ) );
        if ( ! $this->verify_timestamp( $timestamp ) ) return new WP_Error( 'timestamp_old', 'Timestamp expiré', array( 'status' => 403 ) );
        if ( ! $this->verify_signature( $signature, $timestamp ) ) return new WP_Error( 'sig_invalid', 'Signature invalide', array( 'status' => 403 ) );

        // Réinitialise le compteur sur auth réussie
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

    private function get_client_ip() {
        $ip_keys = array('HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR');
        foreach ( $ip_keys as $key ) {
            if ( array_key_exists( $key, $_SERVER ) ) {
                $ip = explode( ',', $_SERVER[ $key ] );
                $ip = trim( $ip[0] );
                if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) return $ip;
            }
        }
        return '0.0.0.0';
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

    private function verify_token( $token ) {
        return hash_equals( $this->security_token, $token );
    }

    private function verify_timestamp( $timestamp ) {
        if ( empty( $timestamp ) || ! is_numeric( $timestamp ) ) return false;
        $diff = abs( time() - $timestamp );
        return $diff <= $this->timestamp_tolerance;
    }

    private function verify_signature( $provided_signature, $timestamp ) {
        $site_url = get_site_url();
        $site_url_clean = rtrim($site_url, '/'); 
        
        $message1 = $site_url . '|' . $timestamp;
        $message2 = $site_url_clean . '|' . $timestamp;
        
        $expected1 = hash_hmac( 'sha256', $message1, $this->security_token );
        $expected2 = hash_hmac( 'sha256', $message2, $this->security_token );
        
        return hash_equals( $expected1, $provided_signature ) || hash_equals( $expected2, $provided_signature );
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

    // 2. NOUVEAU : La mise à jour à distance
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
    'https://github.com/Romain-mont/werocket-agent-wp', 
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