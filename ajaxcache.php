<?php
/*
Plugin Name: Enterprise AJAX Cache
Description: A production-ready AJAX caching system for WordPress.
Version: 1.0.0
Author: WordPress Developer
Author URI: https://example.com
Text Domain: enterprise-ajax-cache
Domain Path: /languages
License: GPL v2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.txt
*/

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Constants for version requirements
 */
define('AJAX_CACHE_MIN_PHP_VERSION', '7.2');
define('AJAX_CACHE_MIN_WP_VERSION', '5.0');
define('AJAX_CACHE_MIN_MYSQL_VERSION', '5.6');

/**
 * Logger class for Enterprise AJAX Cache
 */
class Ajax_Cache_Logger {
    const LOG_NONE = 0;
    const LOG_ERROR = 1;
    const LOG_WARNING = 2;
    const LOG_INFO = 3;
    const LOG_DEBUG = 4;
    
    private static $instance = null;
    private $log_level = self::LOG_ERROR; // Default log level
    
    /**
     * Get the singleton instance
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Constructor
     */
    private function __construct() {
        $this->log_level = apply_filters('ajax_cache_log_level', self::LOG_ERROR);
    }
    
    /**
     * Log a message
     */
    public function log($message, $level = self::LOG_INFO, $context = array()) {
        if ($level > $this->log_level) {
            return false;
        }
        
        $timestamp = current_time('mysql');
        $level_name = $this->get_level_name($level);
        
        $log_message = sprintf("[%s] [%s] %s", $timestamp, $level_name, $message);
        
        if (!empty($context)) {
            $log_message .= ' ' . json_encode($context);
        }
        
        if (defined('WP_DEBUG') && WP_DEBUG && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            error_log($log_message);
        }
        
        do_action('ajax_cache_logged', $message, $level, $context);
        
        return true;
    }
    
    /**
     * Get the name of a log level
     */
    private function get_level_name($level) {
        switch ($level) {
            case self::LOG_ERROR:
                return 'ERROR';
            case self::LOG_WARNING:
                return 'WARNING';
            case self::LOG_INFO:
                return 'INFO';
            case self::LOG_DEBUG:
                return 'DEBUG';
            default:
                return 'UNKNOWN';
        }
    }
    
    /**
     * Log an error
     */
    public function error($message, $context = array()) {
        return $this->log($message, self::LOG_ERROR, $context);
    }
    
    /**
     * Log a warning
     */
    public function warning($message, $context = array()) {
        return $this->log($message, self::LOG_WARNING, $context);
    }
    
    /**
     * Log an info message
     */
    public function info($message, $context = array()) {
        return $this->log($message, self::LOG_INFO, $context);
    }
    
    /**
     * Log a debug message
     */
    public function debug($message, $context = array()) {
        return $this->log($message, self::LOG_DEBUG, $context);
    }
}

// Initialize logger
$ajax_cache_logger = Ajax_Cache_Logger::get_instance();

/**
 * Check system compatibility
 *
 * @return array Compatibility status and issues
 */
function ajax_cache_check_compatibility() {
    $issues = array();
    $compatible = true;
    $logger = Ajax_Cache_Logger::get_instance();
    
    // Check PHP version
    if (version_compare(PHP_VERSION, AJAX_CACHE_MIN_PHP_VERSION, '<')) {
        $compatible = false;
        $issues[] = sprintf(
            __('PHP version %s is required. Your server is running PHP %s.', 'enterprise-ajax-cache'),
            AJAX_CACHE_MIN_PHP_VERSION,
            PHP_VERSION
        );
        $logger->error("PHP version compatibility issue", array(
            'required' => AJAX_CACHE_MIN_PHP_VERSION,
            'current' => PHP_VERSION
        ));
    }
    
    // Check WordPress version
    $wp_version = get_bloginfo('version');
    if (version_compare($wp_version, AJAX_CACHE_MIN_WP_VERSION, '<')) {
        $compatible = false;
        $issues[] = sprintf(
            __('WordPress version %s is required. Your site is running WordPress %s.', 'enterprise-ajax-cache'),
            AJAX_CACHE_MIN_WP_VERSION,
            $wp_version
        );
        $logger->error("WordPress version compatibility issue", array(
            'required' => AJAX_CACHE_MIN_WP_VERSION,
            'current' => $wp_version
        ));
    }
    
    // Check MySQL version
    global $wpdb;
    $mysql_version = $wpdb->db_version();
    if (version_compare($mysql_version, AJAX_CACHE_MIN_MYSQL_VERSION, '<')) {
        $compatible = false;
        $issues[] = sprintf(
            __('MySQL version %s is required. Your server is running MySQL %s.', 'enterprise-ajax-cache'),
            AJAX_CACHE_MIN_MYSQL_VERSION,
            $mysql_version
        );
        $logger->error("MySQL version compatibility issue", array(
            'required' => AJAX_CACHE_MIN_MYSQL_VERSION,
            'current' => $mysql_version
        ));
    }
    
    return array(
        'compatible' => $compatible,
        'issues' => $issues
    );
}

/**
 * Display compatibility notices
 */
function ajax_cache_compatibility_notices() {
    $check = ajax_cache_check_compatibility();
    
    if (!$check['compatible']) {
        echo '<div class="error notice">';
        echo '<p><strong>' . __('Enterprise AJAX Cache - Compatibility Issues', 'enterprise-ajax-cache') . '</strong></p>';
        echo '<ul>';
        
        foreach ($check['issues'] as $issue) {
            echo '<li>' . esc_html($issue) . '</li>';
        }
        
        echo '</ul>';
        echo '<p>' . __('Please resolve these issues to ensure proper functionality.', 'enterprise-ajax-cache') . '</p>';
        echo '</div>';
    }
}
add_action('admin_notices', 'ajax_cache_compatibility_notices');

/**
 * Display activation error notice
 */
function ajax_cache_activation_error_notice() {
    $issues = get_transient('ajax_cache_activation_error');
    
    if ($issues) {
        echo '<div class="error notice">';
        echo '<p><strong>' . __('Enterprise AJAX Cache could not be activated due to compatibility issues:', 'enterprise-ajax-cache') . '</strong></p>';
        echo '<ul>';
        
        foreach ($issues as $issue) {
            echo '<li>' . esc_html($issue) . '</li>';
        }
        
        echo '</ul>';
        echo '</div>';
        
        delete_transient('ajax_cache_activation_error');
    }
}
add_action('admin_notices', 'ajax_cache_activation_error_notice');

/**
 * Initialize AJAX caching on admin_init
 */
function ajax_cache_init() {
    $logger = Ajax_Cache_Logger::get_instance();
    
    if (defined('DOING_AJAX') && DOING_AJAX && isset($_REQUEST['action'])) {
        $action = sanitize_key($_REQUEST['action']);
        $logger->debug("Processing AJAX request for action: {$action}");
        
        // Check if the action is cacheable
        if (is_cacheable_action($action)) {
            $logger->debug("Action {$action} is cacheable");
            $cache_key = generate_cache_key($action);
            $cached_response = get_cached_response($cache_key);

            // Serve cached response if available
            if ($cached_response !== false) {
                $logger->debug("Cache hit for action {$action}", array('key' => $cache_key));
                echo $cached_response;
                wp_die();
            } else {
                $logger->debug("Cache miss for action {$action}", array('key' => $cache_key));
                // Start output buffering with a callback to cache the response
                ob_start(function ($output) use ($cache_key, $action, $logger) {
                    if (!empty($output)) {
                        $logger->debug("Caching output for action {$action}", array('key' => $cache_key));
                        cache_response($cache_key, $output);
                    }
                    return $output;
                });
            }
        }
    }
}
add_action('admin_init', 'ajax_cache_init');

/**
 * Determine if an AJAX action is cacheable
 *
 * @param string $action The AJAX action name
 * @return bool
 */
function is_cacheable_action($action) {
    $cacheable_actions = apply_filters('ajax_cacheable_actions', []);
    return in_array($action, (array)$cacheable_actions, true);
}

/**
 * Generate a unique cache key based on request and context
 *
 * @param string $action The AJAX action name
 * @return string The cache key
 */
function generate_cache_key($action) {
    $params = apply_filters('ajax_cache_key_params', [], $action);
    $factors = apply_filters('ajax_cache_key_factors', [], $action);
    $cookies = apply_filters('ajax_cache_key_cookies', [], $action);
    $logger = Ajax_Cache_Logger::get_instance();

    $key_parts = [$action];

    // Include specified request parameters
    foreach ((array)$params as $param) {
        if (isset($_REQUEST[$param])) {
            $key_parts[] = $param . '=' . sanitize_text_field($_REQUEST[$param]);
        }
    }

    // Include user-specific factors
    if (in_array('user_id', (array)$factors, true)) {
        $key_parts[] = 'user_id=' . get_current_user_id();
    }
    if (in_array('user_roles', (array)$factors, true)) {
        $user = wp_get_current_user();
        $roles = $user->roles ? $user->roles : ['none'];
        sort($roles);
        $key_parts[] = 'user_roles=' . implode(',', $roles);
    }

    // Include specified cookies
    foreach ((array)$cookies as $cookie) {
        if (isset($_COOKIE[$cookie])) {
            $key_parts[] = $cookie . '=' . sanitize_text_field($_COOKIE[$cookie]);
        }
    }

    $key = implode('&', $key_parts);
    $hashed_key = hash('sha256', $key); // Use SHA-256 for better uniqueness
    
    $logger->debug("Generated cache key for action {$action}", array(
        'key_parts' => $key_parts,
        'hashed_key' => $hashed_key
    ));
    
    return $hashed_key;
}

/**
 * Retrieve a cached response with support for external cache backends
 *
 * @param string $cache_key The cache key
 * @return mixed The cached response or false if not found
 */
function get_cached_response($cache_key) {
    $logger = Ajax_Cache_Logger::get_instance();
    $full_key = 'ajax_cache_' . $cache_key;
    
    $stats = get_option('ajax_cache_stats', array(
        'hits' => 0,
        'misses' => 0,
        'sets' => 0,
        'purges' => 0,
        'last_purge' => 0
    ));
    
    try {
        // Use Redis if available and configured
        if (function_exists('wp_redis') && defined('WP_REDIS_ENABLED') && WP_REDIS_ENABLED) {
            $logger->debug("Attempting to get cache from Redis", array('key' => $full_key));
            $cached = wp_redis()->get($full_key);
            
            if ($cached !== false) {
                $stats['hits']++;
                update_option('ajax_cache_stats', $stats);
                return $cached;
            }
        }
        
        // Use Memcached if available
        if (class_exists('WP_Object_Cache') && isset($GLOBALS['wp_object_cache']) && 
            method_exists($GLOBALS['wp_object_cache'], 'get_with_fallback') && 
            $GLOBALS['wp_object_cache']->is_memcache) {
            
            $logger->debug("Attempting to get cache from Memcached", array('key' => $full_key));
            $cached = $GLOBALS['wp_object_cache']->get_with_fallback($full_key, null);
            
            if ($cached !== null) {
                $stats['hits']++;
                update_option('ajax_cache_stats', $stats);
                return $cached;
            }
        }
        
        // Default to WordPress transients
        $logger->debug("Attempting to get cache from transients", array('key' => $full_key));
        $cached = get_transient($full_key);
        
        if ($cached !== false) {
            $stats['hits']++;
            update_option('ajax_cache_stats', $stats);
            return $cached;
        }
        
        // Cache miss
        $stats['misses']++;
        update_option('ajax_cache_stats', $stats);
        return false;
    } catch (Exception $e) {
        $logger->error("Exception in get_cached_response: " . $e->getMessage(), array(
            'key' => $cache_key,
            'exception' => get_class($e),
            'trace' => $e->getTraceAsString()
        ));
        
        // Cache miss due to exception
        $stats['misses']++;
        update_option('ajax_cache_stats', $stats);
        return false;
    }
}

/**
 * Cache an AJAX response with support for external cache backends
 *
 * @param string $cache_key The cache key
 * @param string $response The response to cache
 * @return bool Success or failure
 */
function cache_response($cache_key, $response) {
    $logger = Ajax_Cache_Logger::get_instance();
    $stats = get_option('ajax_cache_stats', array(
        'hits' => 0,
        'misses' => 0,
        'sets' => 0,
        'purges' => 0,
        'last_purge' => 0
    ));
    
    try {
        $full_key = 'ajax_cache_' . $cache_key;
        $expiration = apply_filters('ajax_cache_expiration', 3600, $cache_key);
        
        // Use Redis if available and configured
        if (function_exists('wp_redis') && defined('WP_REDIS_ENABLED') && WP_REDIS_ENABLED) {
            $logger->debug("Attempting to set cache in Redis", array(
                'key' => $full_key,
                'expiration' => $expiration
            ));
            
            $result = wp_redis()->set($full_key, $response, $expiration);
            if (!$result) {
                $logger->warning("Failed to set Redis cache for key {$cache_key}", array(
                    'key' => $cache_key,
                    'expiration' => $expiration
                ));
            } else {
                $stats['sets']++;
                update_option('ajax_cache_stats', $stats);
            }
            return $result;
        }
        
        // Use Memcached if available
        if (class_exists('WP_Object_Cache') && isset($GLOBALS['wp_object_cache']) && 
            method_exists($GLOBALS['wp_object_cache'], 'set') && 
            $GLOBALS['wp_object_cache']->is_memcache) {
            
            $logger->debug("Attempting to set cache in Memcached", array(
                'key' => $full_key,
                'expiration' => $expiration
            ));
            
            $result = $GLOBALS['wp_object_cache']->set($full_key, $response, 'default', $expiration);
            if (!$result) {
                $logger->warning("Failed to set Memcached cache for key {$cache_key}", array(
                    'key' => $cache_key,
                    'expiration' => $expiration
                ));
            } else {
                $stats['sets']++;
                update_option('ajax_cache_stats', $stats);
            }
            return $result;
        }
        
        // Default to WordPress transients
        $logger->debug("Attempting to set cache in transients", array(
            'key' => $full_key,
            'expiration' => $expiration
        ));
        
        $result = set_transient($full_key, $response, $expiration);
        if (!$result) {
            $logger->warning("Failed to set transient cache for key {$cache_key}", array(
                'key' => $cache_key,
                'expiration' => $expiration
            ));
        } else {
            $stats['sets']++;
            update_option('ajax_cache_stats', $stats);
        }
        
        return $result;
    } catch (Exception $e) {
        $logger->error("Exception in cache_response: " . $e->getMessage(), array(
            'key' => $cache_key,
            'exception' => get_class($e),
            'trace' => $e->getTraceAsString()
        ));
        return false;
    }
}

/**
 * Purge cache for a specific action (SQL-Injection safe version)
 *
 * @param string $action The AJAX action to purge
 */
function purge_ajax_cache_by_action($action) {
    global $wpdb;
    $logger = Ajax_Cache_Logger::get_instance();
    $stats = get_option('ajax_cache_stats', array(
        'hits' => 0,
        'misses' => 0,
        'sets' => 0,
        'purges' => 0,
        'last_purge' => time()
    ));
    
    $prefix = 'ajax_cache_';
    
    $logger->info("Purging cache for action: {$action}");
    
    // Generate an action hash similar to how we store it
    $action_hash = hash('sha256', $action);
    
    // Use more targeted query without REGEXP
    $like = $wpdb->esc_like($prefix) . '%';
    
    // Get all cache keys
    $keys = $wpdb->get_col(
        $wpdb->prepare(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
            $like
        )
    );
    
    // Filter keys that match our action pattern
    $keys_to_delete = array();
    foreach ($keys as $key) {
        // Extract the hash portion
        $key_hash = substr($key, strlen($prefix));
        
        // Check if this key was generated for our action
        if (strpos($key_hash, substr($action_hash, 0, 10)) === 0) {
            $keys_to_delete[] = $key;
        }
    }
    
    // Delete matching keys
    $count = 0;
    if (!empty($keys_to_delete)) {
        foreach ($keys_to_delete as $key) {
            if (delete_option($key)) {
                $count++;
            }
        }
    }
    
    $stats['purges']++;
    $stats['last_purge'] = time();
    update_option('ajax_cache_stats', $stats);
    
    $logger->info("Purged {$count} cache entries for action: {$action}");
    
    do_action('ajax_cache_purged', $action, $count);
    
    return $count;
}

/**
 * Purge all AJAX caches (SQL-Injection safe version)
 */
function purge_all_ajax_caches() {
    global $wpdb;
    $logger = Ajax_Cache_Logger::get_instance();
    $stats = get_option('ajax_cache_stats', array(
        'hits' => 0,
        'misses' => 0,
        'sets' => 0,
        'purges' => 0,
        'last_purge' => time()
    ));
    
    $prefix = 'ajax_cache_';
    $like = $wpdb->esc_like($prefix) . '%';
    
    $logger->info("Purging all AJAX caches");
    
    // Get all cache keys
    $keys = $wpdb->get_col(
        $wpdb->prepare(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
            $like
        )
    );
    
    // Delete all matching keys
    $count = 0;
    if (!empty($keys)) {
        foreach ($keys as $key) {
            if (delete_option($key)) {
                $count++;
            }
        }
    }
    
    $stats['purges']++;
    $stats['last_purge'] = time();
    update_option('ajax_cache_stats', $stats);
    
    $logger->info("Purged {$count} total cache entries");
    
    do_action('ajax_cache_purged_all', $count);
    return $count;
}

/**
 * Register the plugin settings page
 */
function ajax_cache_add_admin_menu() {
    add_management_page(
        __('Enterprise AJAX Cache', 'enterprise-ajax-cache'),
        __('AJAX Cache', 'enterprise-ajax-cache'),
        'manage_options',
        'enterprise-ajax-cache',
        'ajax_cache_settings_page'
    );
}
add_action('admin_menu', 'ajax_cache_add_admin_menu');

/**
 * Display the plugin settings page
 */
function ajax_cache_settings_page() {
    // Check user capabilities
    if (!current_user_can('manage_options')) {
        return;
    }

    $logger = Ajax_Cache_Logger::get_instance();
    
    // Handle form submissions
    if (isset($_POST['clear_all_caches']) && check_admin_referer('ajax_cache_clear_all')) {
        $count = purge_all_ajax_caches();
        add_settings_error(
            'ajax_cache_messages',
            'ajax_cache_message',
            sprintf(
                __('All AJAX caches have been cleared. (%d entries removed)', 'enterprise-ajax-cache'),
                $count
            ),
            'updated'
        );
    }

    if (isset($_POST['clear_specific_cache']) && check_admin_referer('ajax_cache_clear_specific')) {
        $action = sanitize_key($_POST['cache_action']);
        if (!empty($action)) {
            $count = purge_ajax_cache_by_action($action);
            add_settings_error(
                'ajax_cache_messages',
                'ajax_cache_message',
                sprintf(
                    __('Cache for action "%s" has been cleared. (%d entries removed)', 'enterprise-ajax-cache'),
                    $action,
                    $count
                ),
                'updated'
            );
        }
    }

    // Get list of cacheable actions
    $cacheable_actions = apply_filters('ajax_cacheable_actions', []);
    
    // Get cache statistics
    $stats = get_option('ajax_cache_stats', array(
        'hits' => 0,
        'misses' => 0,
        'sets' => 0,
        'purges' => 0,
        'last_purge' => 0
    ));
    
    // Check system compatibility
    $compatibility = ajax_cache_check_compatibility();
    ?>
    <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
        
        <?php settings_errors('ajax_cache_messages'); ?>

        <?php if (!$compatibility['compatible']): ?>
        <div class="notice notice-error">
            <p><strong><?php _e('System Compatibility Issues Detected', 'enterprise-ajax-cache'); ?></strong></p>
            <ul>
                <?php foreach ($compatibility['issues'] as $issue): ?>
                    <li><?php echo esc_html($issue); ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
        <?php endif; ?>

        <div class="card">
            <h2><?php _e('About AJAX Caching', 'enterprise-ajax-cache'); ?></h2>
            <p><?php _e('This plugin provides a caching system for AJAX requests, improving performance for frequently accessed data.', 'enterprise-ajax-cache'); ?></p>
            
            <h3><?php _e('Currently Cached Actions', 'enterprise-ajax-cache'); ?></h3>
            <?php if (empty($cacheable_actions)) : ?>
                <p><?php _e('No AJAX actions are currently configured for caching.', 'enterprise-ajax-cache'); ?></p>
            <?php else : ?>
                <ul>
                    <?php foreach ($cacheable_actions as $action) : ?>
                        <li><?php echo esc_html($action); ?></li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>

        <div class="card">
            <h2><?php _e('Cache Statistics', 'enterprise-ajax-cache'); ?></h2>
            <p><?php _e('Performance metrics for your AJAX cache:', 'enterprise-ajax-cache'); ?></p>
            <ul>
                <li><?php echo sprintf(__('Cache Hits: %d', 'enterprise-ajax-cache'), $stats['hits']); ?></li>
                <li><?php echo sprintf(__('Cache Misses: %d', 'enterprise-ajax-cache'), $stats['misses']); ?></li>
                <li><?php echo sprintf(__('Cache Hit Ratio: %s%%', 'enterprise-ajax-cache'),
                    ($stats['hits'] + $stats['misses'] > 0) ?
                    round(($stats['hits'] / ($stats['hits'] + $stats['misses'])) * 100, 2) : 0); ?></li>
                <li><?php echo sprintf(__('Cache Sets: %d', 'enterprise-ajax-cache'), $stats['sets']); ?></li>
                <li><?php echo sprintf(__('Cache Purges: %d', 'enterprise-ajax-cache'), $stats['purges']); ?></li>
                <?php if ($stats['last_purge'] > 0): ?>
                <li><?php echo sprintf(__('Last Purge: %s', 'enterprise-ajax-cache'), 
                    date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $stats['last_purge'])); ?></li>
                <?php endif; ?>
            </ul>
        </div>

        <div class="card">
            <h2><?php _e('Clear All Caches', 'enterprise-ajax-cache'); ?></h2>
            <form method="post" action="">
                <?php wp_nonce_field('ajax_cache_clear_all'); ?>
                <p><?php _e('Use this option to clear all AJAX caches at once.', 'enterprise-ajax-cache'); ?></p>
                <p>
                    <input type="submit" name="clear_all_caches" id="clear_all_caches" class="button button-primary" 
                        value="<?php _e('Clear All Caches', 'enterprise-ajax-cache'); ?>">
                </p>
            </form>
        </div>

        <div class="card">
            <h2><?php _e('Clear Specific Cache', 'enterprise-ajax-cache'); ?></h2>
            <form method="post" action="">
                <?php wp_nonce_field('ajax_cache_clear_specific'); ?>
                <p><?php _e('Select an AJAX action to clear its cache.', 'enterprise-ajax-cache'); ?></p>
                <p>
                    <select name="cache_action" id="cache_action">
                        <?php foreach ($cacheable_actions as $action) : ?>
                            <option value="<?php echo esc_attr($action); ?>"><?php echo esc_html($action); ?></option>
                        <?php endforeach; ?>
                    </select>
                </p>
                <p>
                    <input type="submit" name="clear_specific_cache" id="clear_specific_cache" class="button button-secondary" 
                        value="<?php _e('Clear Selected Cache', 'enterprise-ajax-cache'); ?>" 
                        <?php disabled(empty($cacheable_actions)); ?>>
                </p>
            </form>
        </div>

        <div class="card">
            <h2><?php _e('Cache Storage Configuration', 'enterprise-ajax-cache'); ?></h2>
            <p><?php _e('Current cache backend:', 'enterprise-ajax-cache'); ?></p>
            <ul>
                <?php if (function_exists('wp_redis') && defined('WP_REDIS_ENABLED') && WP_REDIS_ENABLED): ?>
                    <li><strong><?php _e('Redis', 'enterprise-ajax-cache'); ?></strong> - <?php _e('High-performance object caching enabled', 'enterprise-ajax-cache'); ?></li>
                <?php elseif (class_exists('WP_Object_Cache') && isset($GLOBALS['wp_object_cache']) && 
                    method_exists($GLOBALS['wp_object_cache'], 'get_with_fallback') && 
                    $GLOBALS['wp_object_cache']->is_memcache): ?>
                    <li><strong><?php _e('Memcached', 'enterprise-ajax-cache'); ?></strong> - <?php _e('Distributed memory object caching system enabled', 'enterprise-ajax-cache'); ?></li>
                <?php else: ?>
                    <li><strong><?php _e('WordPress Transients', 'enterprise-ajax-cache'); ?></strong> - <?php _e('Default WordPress database storage', 'enterprise-ajax-cache'); ?></li>
                    <li><?php _e('For better performance, consider installing Redis or Memcached.', 'enterprise-ajax-cache'); ?></li>
                <?php endif; ?>
            </ul>
        </div>

        <div class="card">
            <h2><?php _e('Developer Documentation', 'enterprise-ajax-cache'); ?></h2>
            <h3><?php _e('How to Make an AJAX Action Cacheable', 'enterprise-ajax-cache'); ?></h3>
            <pre>
add_filter('ajax_cacheable_actions', function ($actions) {
    $actions[] = 'my_custom_action';
    return $actions;
});
            </pre>

            <h3><?php _e('How to Include Request Parameters in Cache Key', 'enterprise-ajax-cache'); ?></h3>
            <pre>
add_filter('ajax_cache_key_params', function ($params, $action) {
    if ($action === 'my_custom_action') {
        $params[] = 'item_id';
    }
    return $params;
}, 10, 2);
            </pre>

            <h3><?php _e('How to Make Cache User-Specific', 'enterprise-ajax-cache'); ?></h3>
            <pre>
add_filter('ajax_cache_key_factors', function ($factors, $action) {
    if ($action === 'my_custom_action') {
        $factors[] = 'user_id';
        $factors[] = 'user_roles';
    }
    return $factors;
}, 10, 2);
            </pre>

            <h3><?php _e('How to Change Cache Expiration', 'enterprise-ajax-cache'); ?></h3>
            <pre>
add_filter('ajax_cache_expiration', function ($expiration, $cache_key) {
    // Set expiration to 30 minutes for specific action
    if (strpos($cache_key, 'my_custom_action') === 0) {
        return 30 * 60; // 30 minutes in seconds
    }
    return $expiration;
}, 10, 2);
            </pre>
            
            <h3><?php _e('How to Set Logging Level', 'enterprise-ajax-cache'); ?></h3>
            <pre>
add_filter('ajax_cache_log_level', function ($level) {
    // Set to a more verbose level during development
    return Ajax_Cache_Logger::LOG_DEBUG; // Options: LOG_NONE, LOG_ERROR, LOG_WARNING, LOG_INFO, LOG_DEBUG
});
            </pre>
        </div>
    </div>
    <?php
}

/**
 * Automatically invalidate caches when posts are updated
 *
 * @param int $post_id The ID of the post being saved
 */
function invalidate_ajax_cache_on_post_save($post_id) {
    $logger = Ajax_Cache_Logger::get_instance();
    
    // Don't run on autosave
    if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
        return;
    }

    // Check if the post type should trigger invalidation
    $post_type = get_post_type($post_id);
    $post_types_to_watch = apply_filters('ajax_cache_watched_post_types', ['post', 'page']);
    
    if (in_array($post_type, $post_types_to_watch, true)) {
        $logger->info("Post update detected for type {$post_type}, checking cache invalidation", array('post_id' => $post_id));
        
        $actions_to_invalidate = apply_filters('ajax_cache_invalidate_on_post_save', [], $post_id, $post_type);
        
        if (!empty($actions_to_invalidate)) {
            $logger->info("Actions to invalidate: " . implode(', ', $actions_to_invalidate));
            
            foreach ($actions_to_invalidate as $action) {
                purge_ajax_cache_by_action($action);
            }
        }
    }
}
add_action('save_post', 'invalidate_ajax_cache_on_post_save');

/**
 * Enhanced plugin activation with compatibility check
 */
function ajax_cache_activate() {
    $logger = Ajax_Cache_Logger::get_instance();
    $logger->info("Plugin activation started");
    
    $check = ajax_cache_check_compatibility();
    
    if (!$check['compatible']) {
        // Log the compatibility issues
        $logger->error("Plugin activation aborted due to compatibility issues", array(
            'issues' => $check['issues']
        ));
        
        // Deactivate the plugin
        deactivate_plugins(plugin_basename(__FILE__));
        
        // Add transient for admin notice
        set_transient('ajax_cache_activation_error', $check['issues'], 5 * 60);
        
        // Redirect to plugins page with error
        wp_redirect(admin_url('plugins.php?error=true'));
        exit;
    }
    
    // Add activation tasks
    add_option('ajax_cache_activated', true);
    add_option('ajax_cache_version', '1.0.0');
    
    // Initialize cache statistics
    add_option('ajax_cache_stats', array(
        'hits' => 0,
        'misses' => 0,
        'sets' => 0,
        'purges' => 0,
        'last_purge' => 0
    ));
    
    $logger->info("Plugin activated successfully");
}
register_activation_hook(__FILE__, 'ajax_cache_activate');

/**
 * Plugin deactivation hook
 */
function ajax_cache_deactivate() {
    $logger = Ajax_Cache_Logger::get_instance();
    $logger->info("Plugin deactivation started");
    
    // Clean up on deactivation
    purge_all_ajax_caches();
    
    $logger->info("Plugin deactivated successfully");
}
register_deactivation_hook(__FILE__, 'ajax_cache_deactivate');

/**
 * Plugin uninstall hook (must be registered in a separate file)
 */
function ajax_cache_uninstall() {
    // Clean up options
    delete_option('ajax_cache_activated');
    delete_option('ajax_cache_version');
    delete_option('ajax_cache_stats');
    
    // Remove all caches
    purge_all_ajax_caches();
}

// Example usage for WooCommerce
add_filter('ajax_cacheable_actions', function ($actions) {
    $actions[] = 'wc_get_cart_contents'; // Custom WooCommerce action (example)
    return $actions;
});

add_filter('ajax_cache_key_cookies', function ($cookies, $action) {
    if ($action === 'wc_get_cart_contents') {
        $cookies[] = 'woocommerce_cart_hash';
    }
    return $cookies;
}, 10, 2);

// Example usage for a membership plugin
add_filter('ajax_cacheable_actions', function ($actions) {
    $actions[] = 'membership_dashboard_data'; // Hypothetical action
    return $actions;
});

add_filter('ajax_cache_key_factors', function ($factors, $action) {
    if ($action === 'membership_dashboard_data') {
        $factors[] = 'user_id';
        $factors[] = 'user_roles';
    }
    return $factors;
}, 10, 2);

// Example usage for a page builder
add_filter('ajax_cacheable_actions', function ($actions) {
    $actions[] = 'page_builder_load_template'; // Hypothetical action
    return $actions;
});

add_filter('ajax_cache_key_params', function ($params, $action) {
    if ($action === 'page_builder_load_template') {
        $params[] = 'template_id';
    }
    return $params;
}, 10, 2);

// Add cache invalidation on WooCommerce product updates
add_filter('ajax_cache_watched_post_types', function ($post_types) {
    $post_types[] = 'product';
    return $post_types;
});

add_filter('ajax_cache_invalidate_on_post_save', function ($actions, $post_id, $post_type) {
    if ($post_type === 'product') {
        $actions[] = 'wc_get_cart_contents';
    }
    return $actions;
}, 10, 3);
