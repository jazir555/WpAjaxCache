Plugin Name: Enterprise AJAX Cache
Description: A production-ready AJAX caching system for WordPress.
Version: 1.0.1
Author: WordPress Developer
Author URI: https://example.com
Text Domain: enterprise-ajax-cache
Domain Path: /languages
License: GPL v2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.txt
Requires PHP: 7.2
Requires at least: 5.0
*/

// Prevent direct access
if (!defined('ABSPATH')) {
	exit;
}

/**
 * Constants
 */
define('AJAX_CACHE_MIN_PHP_VERSION', '7.2');
define('AJAX_CACHE_MIN_WP_VERSION', '5.0');
define('AJAX_CACHE_MIN_MYSQL_VERSION', '5.6'); // Note: WP requires 5.6+ anyway since WP 5.2
define('AJAX_CACHE_SETTINGS_KEY', 'enterprise_ajax_cache_settings');
define('AJAX_CACHE_PLUGIN_FILE', __FILE__);
define('AJAX_CACHE_VERSION', '1.0.1');
define('AJAX_CACHE_LOG_OPTION', 'ajax_cache_logs');
define('AJAX_CACHE_STATS_OPTION', 'ajax_cache_stats');
define('AJAX_CACHE_TRANSIENT_PREFIX', 'ajax_cache_');

// Ensure compatibility before loading the plugin class
if (version_compare(PHP_VERSION, AJAX_CACHE_MIN_PHP_VERSION, '<') || version_compare(get_bloginfo('version'), AJAX_CACHE_MIN_WP_VERSION, '<')) {
	add_action('admin_notices', 'ajax_cache_compatibility_error_notice');
	return; // Stop loading the plugin
}

/**
 * Display compatibility error notice if PHP or WP version is too low.
 */
function ajax_cache_compatibility_error_notice() {
	$issues = [];
	if (version_compare(PHP_VERSION, AJAX_CACHE_MIN_PHP_VERSION, '<')) {
		$issues[] = sprintf(
			__('PHP version %s or higher is required. Your server is running PHP %s.', 'enterprise-ajax-cache'),
			AJAX_CACHE_MIN_PHP_VERSION,
			PHP_VERSION
		);
	}
	if (version_compare(get_bloginfo('version'), AJAX_CACHE_MIN_WP_VERSION, '<')) {
		$issues[] = sprintf(
			__('WordPress version %s or higher is required. Your site is running WordPress %s.', 'enterprise-ajax-cache'),
			AJAX_CACHE_MIN_WP_VERSION,
			get_bloginfo('version')
		);
	}

	if (!empty($issues)) {
		echo '<div class="error notice is-dismissible">';
		echo '<p><strong>' . __('Enterprise AJAX Cache - Compatibility Issues', 'enterprise-ajax-cache') . '</strong></p>';
		echo '<ul>';
		foreach ($issues as $issue) {
			echo '<li>' . esc_html($issue) . '</li>';
		}
		echo '</ul>';
		echo '<p>' . __('The plugin has been deactivated. Please update your server environment or WordPress installation.', 'enterprise-ajax-cache') . '</p>';
		echo '</div>';

		// Deactivate the plugin
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		deactivate_plugins(plugin_basename(AJAX_CACHE_PLUGIN_FILE));
	}
}

// Ensure necessary include files exist or handle error
$logger_path = plugin_dir_path(AJAX_CACHE_PLUGIN_FILE) . 'includes/class-ajax-cache-logger.php';
$settings_path = plugin_dir_path(AJAX_CACHE_PLUGIN_FILE) . 'includes/class-enterprise-ajax-cache-settings.php';

if (!file_exists($logger_path) || !file_exists($settings_path)) {
    add_action('admin_notices', function() {
        echo '<div class="error notice"><p><strong>' . __('Enterprise AJAX Cache Error:', 'enterprise-ajax-cache') . '</strong> ' . __('Required plugin files are missing. Please reinstall the plugin.', 'enterprise-ajax-cache') . '</p></div>';
    });
    return; // Stop loading if files are missing
}

require_once $logger_path;
require_once $settings_path;


/**
 * Main plugin class
 */
class Enterprise_AJAX_Cache {
	/**
	 * @var Enterprise_AJAX_Cache Singleton instance
	 */
	private static $instance = null;

	/**
	 * @var Ajax_Cache_Logger Logger instance
	 */
	private $logger;

	/**
	 * @var Enterprise_AJAX_Cache_Settings Settings instance
	 */
	private $settings_instance;

	/**
	 * @var array Plugin settings cache
	 */
	private $plugin_settings = [];

	/**
	 * Get the singleton instance
	 *
	 * @return Enterprise_AJAX_Cache
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
		// Ensure logger class is available
		if (!class_exists('Ajax_Cache_Logger')) {
            // This should ideally not happen due to checks above, but as fallback
            error_log('Enterprise AJAX Cache Error: Ajax_Cache_Logger class not found.');
			return;
		}
		$this->logger = Ajax_Cache_Logger::get_instance();

		// Ensure settings class is available
		if (!class_exists('Enterprise_AJAX_Cache_Settings')) {
            error_log('Enterprise AJAX Cache Error: Enterprise_AJAX_Cache_Settings class not found.');
            return;
		}
		$this->settings_instance = new Enterprise_AJAX_Cache_Settings($this);

		// Load settings
		$this->reload_settings();

		// Set up hooks
		$this->setup_hooks();

		// Apply settings that influence behavior immediately
		$this->apply_settings();
	}

	/**
	 * Load or reload plugin settings
	 */
	public function reload_settings() {
		$this->plugin_settings = $this->settings_instance->get_settings();
	}

	/**
	 * Set up plugin hooks
	 */
	private function setup_hooks() {
		// Check compatibility on admin side (MySQL check needs DB access)
		add_action('admin_init', [$this, 'check_mysql_compatibility']);
		add_action('admin_notices', [$this, 'compatibility_notices']);
		add_action('admin_notices', [$this, 'activation_error_notice']);

		// AJAX handling - Hook early to catch AJAX requests
		add_action('init', [$this, 'init_ajax_caching'], 5); // Use 'init' instead of 'admin_init' for broader coverage

		// Post update handling
		add_action('save_post', [$this, 'invalidate_cache_on_post_save'], 10, 1); // Only pass post_id

		// Add debug headers
		add_action('send_headers', [$this, 'add_debug_headers']);

		// Set up auto purge cron job
		add_action('admin_init', [$this, 'setup_auto_purge']); // Setup/clear cron on admin init when settings might change
		add_action('ajax_cache_auto_purge', [$this, 'do_auto_purge']);

		// Custom logging based on settings
		add_action('ajax_cache_logged', [$this, 'handle_custom_logging'], 10, 3);

        // Action to clear logs from settings page
        add_action('admin_action_ajax_cache_clear_logs', [$this, 'handle_clear_logs']);
        add_action('admin_action_ajax_cache_clear_log_file', [$this, 'handle_clear_log_file']);
	}

	/**
	 * Get the logger instance
	 *
	 * @return Ajax_Cache_Logger
	 */
	public function get_logger() {
		return $this->logger;
	}

	/**
	 * Get the settings instance
	 *
	 * @return Enterprise_AJAX_Cache_Settings
	 */
	public function get_settings_instance() {
		return $this->settings_instance;
	}

	/**
	 * Get plugin settings
	 *
	 * @return array
	 */
	public function get_plugin_settings() {
		// Ensure settings are always fresh if needed, though usually cached
		// $this->reload_settings(); // Uncomment if settings need to be strictly up-to-date everywhere
		return $this->plugin_settings;
	}

	/**
	 * Check MySQL compatibility (run later as it needs DB)
	 */
	public function check_mysql_compatibility() {
		global $wpdb;
		if (empty($wpdb)) {
			return; // Cannot check without $wpdb
		}
		$mysql_version = $wpdb->db_version();
		if ($mysql_version && version_compare($mysql_version, AJAX_CACHE_MIN_MYSQL_VERSION, '<')) {
			$issue = sprintf(
				__('MySQL version %s or higher is required. Your server is running MySQL %s.', 'enterprise-ajax-cache'),
				AJAX_CACHE_MIN_MYSQL_VERSION,
				$mysql_version
			);
			// Store issue temporarily for display
			$transient_key = 'ajax_cache_mysql_compat_error';
			$issues = get_transient($transient_key) ?: [];
			if (!in_array($issue, $issues)) {
				$issues[] = $issue;
				set_transient($transient_key, $issues, MINUTE_IN_SECONDS * 5);
				$this->logger->error("MySQL version compatibility issue", array(
					'required' => AJAX_CACHE_MIN_MYSQL_VERSION,
					'current' => $mysql_version
				));
			}
		}
	}

	/**
	 * Display compatibility notices (MySQL)
	 */
	public function compatibility_notices() {
		$transient_key = 'ajax_cache_mysql_compat_error';
		$issues = get_transient($transient_key);

		if ($issues) {
			echo '<div class="error notice is-dismissible">';
			echo '<p><strong>' . __('Enterprise AJAX Cache - Compatibility Issues', 'enterprise-ajax-cache') . '</strong></p>';
			echo '<ul>';
			foreach ($issues as $issue) {
				echo '<li>' . esc_html($issue) . '</li>';
			}
			echo '</ul>';
			echo '<p>' . __('Please resolve these issues to ensure proper functionality.', 'enterprise-ajax-cache') . '</p>';
			echo '</div>';
			delete_transient($transient_key); // Show only once
		}
	}

	/**
	 * Display activation error notice
	 */
	public function activation_error_notice() {
		$issues = get_transient('ajax_cache_activation_error');

		if ($issues) {
			echo '<div class="error notice is-dismissible">';
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

	/**
	 * Initialize AJAX caching interception
	 */
	public function init_ajax_caching() {
		// Skip if caching is disabled in settings
		if (!$this->plugin_settings['enabled']) {
			return;
		}

		// Only act on AJAX requests
		if (!wp_doing_ajax()) {
			return;
		}

		// Check if action parameter exists
		if (!isset($_REQUEST['action'])) {
			return;
		}

		$action = sanitize_key($_REQUEST['action']);
		$this->logger->debug("Processing AJAX request", array('action' => $action, 'request_uri' => $_SERVER['REQUEST_URI'] ?? 'N/A'));

		// Check if the action is cacheable based on settings
		if ($this->is_cacheable_action($action)) {
			$this->logger->debug("Action '{$action}' is designated as cacheable.");
			$cache_key = $this->generate_cache_key($action);

			if (!$cache_key) {
				$this->logger->warning("Could not generate cache key for action '{$action}'. Bypassing cache.", array('request' => $_REQUEST));
				return; // Don't cache if key generation failed
			}

			$cached_response = $this->get_cached_response($cache_key);

			// Serve cached response if available and valid
			if ($cached_response !== false) {
				$this->logger->info("Cache HIT for action '{$action}'", array('key' => $cache_key));
				// Output the cached response and terminate
				echo $cached_response; // Output directly
				wp_die('', '', ['response' => null]); // Use wp_die correctly for AJAX
			} else {
				$this->logger->info("Cache MISS for action '{$action}'", array('key' => $cache_key));
				// Start output buffering with a callback to cache the response
				ob_start(function ($output) use ($cache_key, $action) {
					// Only cache non-empty, successful responses (basic check)
					// More sophisticated checks (e.g., HTTP status code if possible) could be added here
					if (!empty($output) && http_response_code() < 400) { // Basic check for non-error response
						$this->logger->debug("Attempting to cache output for action '{$action}'", array('key' => $cache_key, 'output_length' => strlen($output)));
						$this->cache_response($cache_key, $output, $action); // Pass action for per-action TTL
					} else {
						$this->logger->debug("Skipping caching for action '{$action}' due to empty or error response.", array('key' => $cache_key, 'http_status' => http_response_code(), 'output_empty' => empty($output)));
					}
					return $output; // Always return the original output
				});
			}
		} else {
			$this->logger->debug("Action '{$action}' is not configured for caching.");
		}
	}

	/**
	 * Determine if an AJAX action is cacheable based on settings
	 *
	 * @param string $action The AJAX action name
	 * @return bool
	 */
	public function is_cacheable_action($action) {
		$settings = $this->plugin_settings;

		// If caching is globally disabled, nothing is cacheable
		if (!$settings['enabled']) {
			return false;
		}

		// Check if this action is explicitly listed in cacheable actions
		$cacheable_actions = apply_filters('ajax_cacheable_actions', $settings['cacheable_actions']);
		return is_array($cacheable_actions) && in_array($action, $cacheable_actions, true);
	}

	/**
	 * Generate a unique cache key based on request and context
	 *
	 * @param string $action The AJAX action name
	 * @return string|false The cache key hash or false on failure
	 */
	public function generate_cache_key($action) {
		$settings = $this->plugin_settings;
		$key_parts = ['action=' . $action]; // Start with the action itself

		// Allow filters to modify base key parts
		$key_parts = apply_filters('ajax_cache_key_base_parts', $key_parts, $action, $_REQUEST);

		try {
			// Include specified request parameters per action
			$param_rules = apply_filters('ajax_cache_key_params', $settings['cache_key_params'], $action);
			if (isset($param_rules[$action]) && is_array($param_rules[$action])) {
				$params_to_include = $param_rules[$action];
				$request_data = wp_unslash($_REQUEST); // Use unsanitized data for key generation, sanitize later if needed for display
				foreach ($params_to_include as $param) {
					if (isset($request_data[$param])) {
						// Serialize complex data types consistently
						$value = is_scalar($request_data[$param]) ? (string) $request_data[$param] : serialize($request_data[$param]);
						$key_parts[] = $param . '=' . $value;
					}
				}
			}

			// Include global user-specific factors
			$factor_rules = apply_filters('ajax_cache_key_factors', $settings['cache_key_factors'], $action);
			if (!empty($factor_rules['user_id'])) {
				$key_parts[] = 'user_id=' . get_current_user_id();
			}
			if (!empty($factor_rules['user_roles'])) {
				$user = wp_get_current_user();
				$roles = ($user && $user->exists() && !empty($user->roles)) ? $user->roles : ['guest'];
				sort($roles);
				$key_parts[] = 'user_roles=' . implode(',', $roles);
			}

			// Include specified cookies per action
			$cookie_rules = apply_filters('ajax_cache_key_cookies', $settings['cache_key_cookies'], $action);
			if (isset($cookie_rules[$action]) && is_array($cookie_rules[$action])) {
				$cookies_to_include = $cookie_rules[$action];
				$cookie_data = wp_unslash($_COOKIE);
				foreach ($cookies_to_include as $cookie) {
					if (isset($cookie_data[$cookie])) {
						$key_parts[] = $cookie . '=' . $cookie_data[$cookie];
					}
				}
			}

			// Allow further modification of key parts
			$key_parts = apply_filters('ajax_cache_key_final_parts', $key_parts, $action, $_REQUEST, $_COOKIE);

			// Sort parts for consistency regardless of order added
			sort($key_parts);
			$raw_key = implode('&', $key_parts);

			// Hash the final raw key
			$hashed_key = hash('sha256', $raw_key);

			$this->logger->debug("Generated cache key for action '{$action}'", array(
				'raw_key' => $raw_key,
				'hashed_key' => $hashed_key
			));

			return $hashed_key;

		} catch (Exception $e) {
			$this->logger->error("Exception during cache key generation for action '{$action}': " . $e->getMessage(), array(
				'exception' => get_class($e),
				'trace' => $e->getTraceAsString()
			));
			return false;
		}
	}

	/**
	 * Retrieve a cached response with support for external cache backends
	 *
	 * @param string $cache_key_hash The hashed cache key
	 * @return mixed The cached response (usually string) or false if not found/error
	 */
	public function get_cached_response($cache_key_hash) {
		$settings = $this->plugin_settings;
		$full_key = AJAX_CACHE_TRANSIENT_PREFIX . $cache_key_hash; // Consistent prefix

		$stats = get_option(AJAX_CACHE_STATS_OPTION, $this->settings_instance->get_default_stats());
		$backend = $settings['cache_backend'];
		$result = false; // Default to cache miss

		try {
			$this->logger->debug("Attempting cache GET", array('key' => $full_key, 'backend' => $backend));

			// Use Redis if selected and properly configured
			if ($backend === 'redis' && class_exists('Redis') && function_exists('wp_redis_get_info')) {
				// Assuming Redis is configured via a plugin like Redis Object Cache or similar
				$redis_info = wp_redis_get_info();
				$redis = $redis_info['client'] ?? null; // Get the Redis instance (adapt if needed)
				if ($redis && method_exists($redis, 'get')) {
					$cached = $redis->get($full_key);
					if ($cached !== false && $cached !== null) { // Redis returns false on failure, null if key doesn't exist
						$this->logger->debug("Redis HIT", array('key' => $full_key));
						$result = $cached;
					} else {
                         $this->logger->debug("Redis MISS", array('key' => $full_key));
                    }
				} else {
                    $this->logger->warning("Redis selected but client unavailable or 'get' method missing.");
                }
			}
			// Use Memcached if selected and WP Object Cache is using it
			elseif ($backend === 'memcached' && wp_using_ext_object_cache()) {
				// Check if the external object cache is indeed Memcached (heuristic)
				// This check might need refinement depending on the specific object cache plugin
                $is_memcached = false;
                if (isset($GLOBALS['wp_object_cache']) && is_object($GLOBALS['wp_object_cache'])) {
                    $cache_class = get_class($GLOBALS['wp_object_cache']);
                    if (stripos($cache_class, 'Memcached') !== false) {
                       $is_memcached = true;
                    }
                    // Some object cache plugins have a specific property
                    if (property_exists($GLOBALS['wp_object_cache'], 'is_memcached')) {
                        $is_memcached = $GLOBALS['wp_object_cache']->is_memcached;
                    } elseif (method_exists($GLOBALS['wp_object_cache'], 'getStats')) {
                         // Check if stats look like memcached stats
                        $stats_data = @$GLOBALS['wp_object_cache']->getStats(); // Suppress potential errors
                        if (is_array($stats_data) && !empty($stats_data)) {
                            $first_server = reset($stats_data);
                            if (isset($first_server['pid']) || isset($first_server['curr_items'])) { // Common memcached stats keys
                               $is_memcached = true;
                            }
                        }
                    }
                }

                if ($is_memcached) {
                    $cached = wp_cache_get($full_key, 'ajax_cache'); // Use a group for potential targeted flushing
                    if ($cached !== false) {
                        $this->logger->debug("Memcached HIT", array('key' => $full_key, 'group' => 'ajax_cache'));
                        $result = $cached;
                    } else {
                        $this->logger->debug("Memcached MISS", array('key' => $full_key, 'group' => 'ajax_cache'));
                    }
                } else {
                     $this->logger->warning("Memcached selected, external cache in use, but doesn't appear to be Memcached.");
                }
			}

			// Default to WordPress transients if no specific backend matched or successful
			if ($result === false) {
				// Transient key doesn't need the '_transient_' prefix
				$transient_key = AJAX_CACHE_TRANSIENT_PREFIX . $cache_key_hash;
				$cached = get_transient($transient_key);

				if ($cached !== false) {
					$this->logger->debug("Transients HIT", array('key' => $transient_key));
					$result = $cached;
				} else {
                    $this->logger->debug("Transients MISS", array('key' => $transient_key));
                }
			}

			// Update stats based on hit/miss
			if ($result !== false) {
				$stats['hits']++;
			} else {
				$stats['misses']++;
			}
			update_option(AJAX_CACHE_STATS_OPTION, $stats);

			return $result; // Return the cached value or false

		} catch (Throwable $e) { // Catch Throwable for wider compatibility (PHP 7+)
			$this->logger->error("Exception in get_cached_response: " . $e->getMessage(), array(
				'key' => $full_key,
				'exception' => get_class($e),
				'trace' => $e->getTraceAsString()
			));

			// Treat exception as cache miss
			$stats['misses']++;
			update_option(AJAX_CACHE_STATS_OPTION, $stats);
			return false;
		}
	}

	/**
	 * Cache an AJAX response with support for external cache backends
	 *
	 * @param string $cache_key_hash The hashed cache key
	 * @param string $response The response content to cache
	 * @param string $action The original AJAX action (for TTL calculation)
	 * @return bool Success or failure
	 */
	public function cache_response($cache_key_hash, $response, $action) {
		$settings = $this->plugin_settings;
		$stats = get_option(AJAX_CACHE_STATS_OPTION, $this->settings_instance->get_default_stats());
		$full_key = AJAX_CACHE_TRANSIENT_PREFIX . $cache_key_hash; // Consistent prefix

		try {
			// Determine expiration time (TTL)
			$expiration = $settings['default_expiration']; // Default TTL
            $per_action_expirations = apply_filters('ajax_cache_per_action_expiration', $settings['per_action_expiration'], $action);
			if (isset($per_action_expirations[$action])) {
				$action_ttl = intval($per_action_expirations[$action]);
				if ($action_ttl >= 0) { // Allow 0 for non-expiring (if backend supports), but generally use >= 1
					$expiration = $action_ttl;
				}
			}
			// Apply global expiration filter
			$expiration = apply_filters('ajax_cache_expiration', $expiration, $action, $cache_key_hash);
			$expiration = max(1, intval($expiration)); // Ensure positive integer TTL

			$backend = $settings['cache_backend'];
			$success = false;
            $log_backend = $backend; // Initialize log backend identifier

			$this->logger->debug("Attempting cache SET", array('key' => $full_key, 'backend' => $backend, 'ttl_seconds' => $expiration));

			// Use Redis if selected and properly configured
            if ($backend === 'redis' && class_exists('Redis') && function_exists('wp_redis_get_info')) {
                $redis_info = wp_redis_get_info();
				$redis = $redis_info['client'] ?? null;
				if ($redis && method_exists($redis, 'setex')) { // Use setex for key with expiration
                    $success = $redis->setex($full_key, $expiration, $response);
                    $log_backend = 'Redis';
				} else {
                    $this->logger->warning("Redis selected but client unavailable or 'setex' method missing.");
                }
			}
			// Use Memcached if selected and WP Object Cache is using it
			elseif ($backend === 'memcached' && wp_using_ext_object_cache()) {
                // Check if external object cache is Memcached (using same heuristic as get_cached_response)
                $is_memcached = false;
                if (isset($GLOBALS['wp_object_cache']) && is_object($GLOBALS['wp_object_cache'])) {
                    $cache_class = get_class($GLOBALS['wp_object_cache']);
                    if (stripos($cache_class, 'Memcached') !== false) {
                       $is_memcached = true;
                    }
                    if (property_exists($GLOBALS['wp_object_cache'], 'is_memcached')) {
                        $is_memcached = $GLOBALS['wp_object_cache']->is_memcached;
                    } elseif (method_exists($GLOBALS['wp_object_cache'], 'getStats')) {
                        $stats_data = @$GLOBALS['wp_object_cache']->getStats();
                        if (is_array($stats_data) && !empty($stats_data)) {
                           $is_memcached = true; // Simplified check
                        }
                    }
                }

                if ($is_memcached) {
					$success = wp_cache_set($full_key, $response, 'ajax_cache', $expiration);
                    $log_backend = 'Memcached';
                } else {
                     $this->logger->warning("Memcached selected, external cache in use, but doesn't appear to be Memcached.");
                }
			}

			// Default to WordPress transients if no specific backend matched or successful
			// Note: We set transient even if Redis/Memcached failed, as a fallback.
            // Check if $success is still false before attempting transient.
			if ($success === false) {
				$transient_key = AJAX_CACHE_TRANSIENT_PREFIX . $cache_key_hash;
				$success = set_transient($transient_key, $response, $expiration);
                $log_backend = 'Transients';
			}

			// Log success/failure and update stats
			if ($success) {
				$stats['sets']++;
				update_option(AJAX_CACHE_STATS_OPTION, $stats);
				$this->logger->debug("Cache SET successful", array('key' => $full_key, 'backend' => $log_backend));
			} else {
				$this->logger->warning("Failed to set cache", array(
					'key' => $full_key,
					'backend' => $log_backend,
                    'ttl_seconds' => $expiration
				));
			}

			return $success;

		} catch (Throwable $e) {
			$this->logger->error("Exception in cache_response: " . $e->getMessage(), array(
				'key' => $full_key,
                'action' => $action,
				'exception' => get_class($e),
				'trace' => $e->getTraceAsString()
			));
			return false;
		}
	}

	/**
	 * Purge caches associated with a specific action.
     * Note: With hashed keys and standard transients, reliably targeting ONLY
     * keys for a specific action without extra indexing is difficult.
     * This function will purge ALL ajax_cache transients as a safer default.
     * For Redis/Memcached, more targeted approaches might be possible if implemented.
	 *
	 * @param string $action The AJAX action to purge
	 * @return int Number of entries potentially purged (returns total count for transient purge)
	 */
	public function purge_cache_by_action($action) {
		$this->logger->info("Purging cache triggered for action: {$action}. Purging ALL AJAX caches due to key structure limitations.");
        // TODO: Implement action-specific purging if using Redis/Memcached with tagging/sets or a custom index.
		return $this->purge_all_caches();
	}


	/**
	 * Purge all AJAX caches managed by this plugin.
	 *
	 * @return int Number of entries purged (or attempted)
	 */
	public function purge_all_caches() {
		global $wpdb;
		$settings = $this->plugin_settings;
		$stats = get_option(AJAX_CACHE_STATS_OPTION, $this->settings_instance->get_default_stats());
		$backend = $settings['cache_backend'];
		$count = 0;

		$this->logger->info("Purging ALL AJAX caches", ['backend' => $backend]);

		try {
            // Purge Redis if active
			if ($backend === 'redis' && class_exists('Redis') && function_exists('wp_redis_get_info')) {
                $redis_info = wp_redis_get_info();
				$redis = $redis_info['client'] ?? null;
                $prefix = AJAX_CACHE_TRANSIENT_PREFIX;
                if ($redis && method_exists($redis, 'scan') && method_exists($redis, 'del')) {
                    $cursor = null;
                    $this->logger->debug("Starting Redis SCAN for prefix '{$prefix}*'");
                    do {
                        // Scan for keys matching the prefix
                        // Using 'null' for cursor persistence is recommended in Predis/phpredis docs
                        $keys = $redis->scan($cursor, $prefix . '*', 100); // Scan in batches of 100
                        if ($keys !== false && !empty($keys)) {
                            // Delete found keys
                            $deleted = $redis->del($keys);
                            $count += (int)$deleted;
                            $this->logger->debug("Redis scan batch: Found " . count($keys) . ", Deleted: {$deleted}");
                        } else if ($keys === false) {
                             $this->logger->warning("Redis SCAN command failed in batch.");
                             break; // Stop if scan fails
                        }
                    } while ($cursor > 0); // Loop until cursor is 0
                    $this->logger->debug("Redis purge: Finished SCAN/DEL. Total Deleted: {$count}");
                } else {
                     $this->logger->warning("Redis selected but SCAN/DEL unavailable. Cannot perform wildcard purge.");
                     // Fallback to DB transient purge if Redis fails? Or just log?
                     $count += $this->purge_transients_via_db();
                }
			}
            // Purge Memcached if active
			elseif ($backend === 'memcached' && wp_using_ext_object_cache()) {
				// Standard WP Object Cache API doesn't support wildcard deletion or group flushing easily.
                // Some plugins might offer flush_group(). Let's try that.
                 $flushed = false;
                if (method_exists($GLOBALS['wp_object_cache'], 'flush_group')) {
                    $flushed = $GLOBALS['wp_object_cache']->flush_group('ajax_cache');
                     $this->logger->debug("Memcached purge: Attempted flush_group('ajax_cache'). Result: " . ($flushed ? 'Success' : 'Failed/Unsupported'));
                    // We don't get a count here easily. If failed, fallback to DB?
                } else {
				    $this->logger->warning("Memcached selected but cannot reliably purge all keys via standard WP API or flush_group().");
                }
                // Always attempt DB transient purge as well, as Memcached might be intermittent or setup wrong
                $db_count = $this->purge_transients_via_db();
                $this->logger->debug("Executed DB transient purge as part of Memcached cleanup.", ['db_deleted' => $db_count]);
                // Reporting count is difficult here, report DB count?
                $count = $db_count; // Or maybe just report success/failure?
			}
            // Purge Transients (Database)
            else {
                 $count = $this->purge_transients_via_db();
            }

			$stats['purges']++;
			$stats['last_purge'] = time();
			update_option(AJAX_CACHE_STATS_OPTION, $stats);

			$this->logger->info("Purge all finished. Approximately {$count} DB transient entries removed (Redis/Memcached count might differ).");
			do_action('ajax_cache_purged_all', $count);
			return $count;

		} catch (Throwable $e) {
			$this->logger->error("Exception during purge_all_caches: " . $e->getMessage(), array(
				'exception' => get_class($e),
				'trace' => $e->getTraceAsString()
			));
			return 0;
		}
	}

    /**
     * Helper function to purge transients via direct DB query.
     *
     * @return int Number of deleted option rows.
     */
    private function purge_transients_via_db() {
        global $wpdb;
        $count = 0;
        // IMPORTANT: Transients have TWO related options rows in wp_options
        // 1. _transient_{key}      (Stores the data)
        // 2. _transient_timeout_{key} (Stores the expiration timestamp)
        // We need to delete both.

        $transient_prefix = '_transient_' . AJAX_CACHE_TRANSIENT_PREFIX;
        $timeout_prefix = '_transient_timeout_' . AJAX_CACHE_TRANSIENT_PREFIX;

        // Escape the prefixes for LIKE clause
        $transient_like = $wpdb->esc_like($transient_prefix) . '%';
        $timeout_like = $wpdb->esc_like($timeout_prefix) . '%';

        // Delete the transient data
        $sql_data = $wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
            $transient_like
        );
        $deleted_data = $wpdb->query($sql_data);

        // Delete the transient timeouts
        $sql_timeouts = $wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
            $timeout_like
        );
        $deleted_timeouts = $wpdb->query($sql_timeouts);

        if ($deleted_data !== false) {
            $count = $deleted_data; // Count represents the number of cache entries
        }

         $this->logger->debug("Transient purge via DB executed.", [
            'data_deleted' => $deleted_data,
            'timeouts_deleted' => $deleted_timeouts
         ]);

        // Clear WP's internal cache of options to reflect DB changes immediately
        // Crucial if an external object cache is *also* being used for options/transients
        wp_cache_flush();

        return (int)$count; // Return count of primary data rows deleted
    }

	/**
	 * Automatically invalidate caches when posts are updated
	 *
	 * @param int $post_id The ID of the post being saved
	 */
	public function invalidate_cache_on_post_save($post_id) {
		// Bail if this is an autosave or revision.
		if (wp_is_post_autosave($post_id) || wp_is_post_revision($post_id)) {
			return;
		}

        // Bail if the post status is not published or transitioning to published
        $post_status = get_post_status($post_id);
        // Allow invalidation for 'publish', 'private', or when trashing/untrashing?
        // Let's stick to published/private for now, might need filter for more statuses.
        if (!in_array($post_status, ['publish', 'private'])) {
            // Check if it's a transition TO publish/private (useful for initial save)
             if (isset($_POST['original_post_status']) && !in_array($_POST['original_post_status'], ['publish', 'private'])) {
                 // It's transitioning to published/private, proceed.
             } else if ($post_status === 'trash') {
                 // Optionally trigger on trash?
                 // return;
             } else {
                 // Not published/private and not transitioning to it, and not trash (or we decided to ignore trash).
                 $this->logger->debug("Post save skipped for invalidation due to status.", ['post_id' => $post_id, 'status' => $post_status]);
                 return;
             }
        }


		// Verify post exists and get post type
        $post = get_post($post_id);
        if (!$post) {
            return;
        }
        $post_type = $post->post_type;

		$settings = $this->plugin_settings;
		$watched_post_types = apply_filters('ajax_cache_watched_post_types', $settings['watched_post_types']);

		// Check if the post type is configured for watching
		if (is_array($watched_post_types) && in_array($post_type, $watched_post_types, true)) {
			$this->logger->info("Post update detected for watched type '{$post_type}'. Checking invalidation rules.", array('post_id' => $post_id, 'status' => $post_status));

			$invalidation_rules = apply_filters('ajax_cache_invalidate_on_post_save', $settings['invalidation_rules'], $post_id, $post_type);

			$actions_to_invalidate = isset($invalidation_rules[$post_type]) && is_array($invalidation_rules[$post_type])
				? $invalidation_rules[$post_type]
				: [];

			if (!empty($actions_to_invalidate)) {
				$this->logger->info("Invalidating specific actions based on rules for post type '{$post_type}'.", array('actions' => $actions_to_invalidate));
                // Since purge_cache_by_action currently purges all, we only need to call it once.
                $this->purge_all_caches(); // Call purge all if *any* rule matches for this post type.
                // If purge_cache_by_action becomes targeted, use the loop:
                // foreach ($actions_to_invalidate as $action) {
				//     $this->purge_cache_by_action($action);
                // }
			} else {
                 $this->logger->info("No specific invalidation rules found for watched post type '{$post_type}', no automatic cache purge triggered by rules.");
                 // Option: Add a global setting 'purge_all_on_watched_post_type_save' ?
                 // if ($settings['purge_all_on_watched_post_type_save']) { $this->purge_all_caches(); }
            }
		}
	}

	/**
	 * Add debug headers to AJAX responses when debug mode is enabled
	 */
	public function add_debug_headers() {
		$settings = $this->plugin_settings;

		// Only add headers during AJAX requests when debug mode is on
		if (!$settings['debug_mode'] || !wp_doing_ajax() || headers_sent()) {
			return;
		}

		$action = isset($_REQUEST['action']) ? sanitize_key($_REQUEST['action']) : '';
		if (empty($action)) {
			return;
		}

		header('X-AJAX-Cache-Plugin: Enterprise AJAX Cache ' . AJAX_CACHE_VERSION);

		// Check if action was *potentially* cacheable (even if missed or disabled globally)
		$cacheable_actions_config = $settings['cacheable_actions']; // Get raw setting for this check
		$is_configured_cacheable = is_array($cacheable_actions_config) && in_array($action, $cacheable_actions_config, true);

		header('X-AJAX-Cache-Action: ' . $action);
        header('X-AJAX-Cache-Config: ' . ($is_configured_cacheable ? 'Cacheable' : 'Not Cacheable'));
		header('X-AJAX-Cache-Status: ' . ($settings['enabled'] ? 'Enabled' : 'Disabled (Global Setting)'));

        // Note: We can't reliably determine Hit/Miss here in 'send_headers' as it runs
        // before the AJAX request is fully processed and cache attempt made.
        // The `init_ajax_caching` method logs Hit/Miss status instead.
        // If needed, one could use a global flag set in `init_ajax_caching`
        // and check it here, but that adds complexity.

        if ($is_configured_cacheable && $settings['enabled']) {
             header('X-AJAX-Cache-Backend: ' . $settings['cache_backend']);
        }
	}

	/**
	 * Setup or clear automatic cache purging cron schedule based on settings
	 */
	public function setup_auto_purge() {
		$settings = $this->plugin_settings;
		$schedule = $settings['auto_purge_schedule'];
		$hook = 'ajax_cache_auto_purge';

		// Clear existing schedule first
		$timestamp = wp_next_scheduled($hook);
		if ($timestamp) {
			wp_unschedule_event($timestamp, $hook);
			$this->logger->debug("Cleared existing auto purge schedule.");
		}

		// Schedule new event if not set to "never" and enabled
		if ($settings['enabled'] && $schedule !== 'never') {
            // Ensure the schedule is valid
            $schedules = wp_get_schedules();
            // Add 'weekly' if it's selected but not registered by WP core/other plugins
            if ($schedule === 'weekly' && !isset($schedules['weekly'])) {
                $schedules['weekly'] = [
                    'interval' => WEEK_IN_SECONDS,
                    'display' => __('Weekly', 'enterprise-ajax-cache') // Display name might not matter here
                ];
            }

            if (isset($schedules[$schedule])) {
                if (!wp_next_scheduled($hook)) { // Double check it wasn't somehow added again
                    // Schedule to run roughly on the interval, but starting in 5 minutes to avoid thundering herd on activation/save.
                    wp_schedule_event(time() + (5 * MINUTE_IN_SECONDS), $schedule, $hook);
                    $this->logger->info("Scheduled auto purge with recurrence: {$schedule}");
                }
            } else {
                 $this->logger->warning("Invalid auto purge schedule '{$schedule}' defined in settings. Auto purge disabled.");
            }
		} else {
             $this->logger->info("Auto purge is disabled (schedule: {$schedule}, enabled: " . ($settings['enabled'] ? 'true' : 'false') . ")");
        }
	}

	/**
	 * Automatic cache purge event callback
	 */
	public function do_auto_purge() {
		$this->logger->info('Running scheduled cache purge...');
		$count = $this->purge_all_caches();
		$this->logger->info(sprintf('Scheduled automatic purge completed, removed approximately %d cache entries', $count));
	}

	/**
	 * Apply settings that affect filters or core behavior
	 */
	public function apply_settings() {
		$settings = $this->plugin_settings;

		// Apply log level to logger instance immediately
		$this->logger->set_log_level($settings['log_level']);

		// Note: Other settings like 'cacheable_actions', 'cache_key_params', etc.,
		// are read directly when needed or applied via filters added within this class.
		// If external code needs to use these settings via filters, ensure those filters
		// are documented and consistently applied.

        // Example of applying settings via filters (already done in constructor/setup_hooks)
		// add_filter('ajax_cache_log_level', function() use ($settings) { return $settings['log_level']; });
	}

    /**
     * Handle custom logging based on destination setting.
     * Hooked to 'ajax_cache_logged'.
     */
    public function handle_custom_logging($message, $level, $context) {
        $settings = $this->plugin_settings;

        // Check if the log level permits this message based on settings
        if ($level > $settings['log_level']) {
            return;
        }

        $timestamp = current_time('mysql');
        $level_name = Ajax_Cache_Logger::get_level_name($level); // Use static helper
        $log_entry = array(
            'timestamp' => $timestamp,
            'level' => $level_name,
            'message' => $message,
            'context' => $context
        );

        // Log based on destination
        switch ($settings['log_destination']) {
            case 'database':
                $logs = get_option(AJAX_CACHE_LOG_OPTION, array());
                array_unshift($logs, $log_entry); // Add to the beginning

                // Trim to max entries
                $max_entries = max(10, intval($settings['log_max_entries'])); // Ensure at least 10
                if (count($logs) > $max_entries) {
                    $logs = array_slice($logs, 0, $max_entries);
                }

                update_option(AJAX_CACHE_LOG_OPTION, $logs, 'no'); // 'no' for autoload
                break;

            case 'file':
                $log_file = $settings['log_file_path']; // Path should be validated/sanitized in settings
                if (!empty($log_file)) {
                    // Ensure directory exists and is writable (basic check)
                    $log_dir = dirname($log_file);
                    if (!is_dir($log_dir)) {
                        // Try to create it (suppress errors, logging handled by error_log potentially)
                        @mkdir($log_dir, 0755, true);
                    }
                    // Check if file is writable or directory is writable if file doesn't exist
                    if ((file_exists($log_file) && is_writable($log_file)) || (!file_exists($log_file) && is_writable($log_dir))) {
                        $formatted_message = sprintf("[%s] [%s] %s %s%s",
                            $timestamp,
                            $level_name,
                            $message,
                            !empty($context) ? wp_json_encode($context) : '', // Use wp_json_encode
                            PHP_EOL // Add newline
                        );
                        // Use ERROR_LOG_APPEND and LOCK_EX for better concurrent writing
                        @error_log($formatted_message, 3, $log_file);
                    } else {
                        // Fallback or log error about unwritable directory/file if desired
                        error_log("Enterprise AJAX Cache Error: Log directory/file not writable: {$log_file}");
                    }
                } else {
                    error_log("Enterprise AJAX Cache Error: Log file path is empty in settings.");
                }
                break;

            case 'wp_debug':
            default:
                // Already handled by the logger using error_log if WP_DEBUG_LOG is on
                break;
        }
    }

    /**
     * Handle request to clear database logs.
     */
    public function handle_clear_logs() {
        if (!current_user_can('manage_options') || !check_admin_referer('clear_ajax_cache_logs', '_wpnonce')) {
            wp_die(__('Security check failed.', 'enterprise-ajax-cache'));
        }

        delete_option(AJAX_CACHE_LOG_OPTION);
        $this->logger->info("Database logs cleared by user.");

        wp_redirect(add_query_arg(array('page' => 'enterprise-ajax-cache', 'tab' => 'logs', 'message' => 'logs-cleared'), admin_url('tools.php')));
        exit;
    }

    /**
     * Handle request to clear log file.
     */
    public function handle_clear_log_file() {
        if (!current_user_can('manage_options') || !check_admin_referer('clear_ajax_cache_log_file', '_wpnonce')) {
            wp_die(__('Security check failed.', 'enterprise-ajax-cache'));
        }

        $settings = $this->get_plugin_settings();
        $log_file = $settings['log_file_path'];

        $cleared = false;
        if (!empty($log_file) && file_exists($log_file) && is_writable($log_file)) {
            $cleared = @file_put_contents($log_file, ''); // Overwrite with empty content
        }

        if ($cleared) {
            $this->logger->info("Log file cleared by user.", ['file' => $log_file]);
            $message = 'log-file-cleared';
        } else {
            $this->logger->error("Failed to clear log file.", ['file' => $log_file]);
            $message = 'log-file-clear-failed';
        }

        wp_redirect(add_query_arg(array('page' => 'enterprise-ajax-cache', 'tab' => 'logs', 'message' => $message), admin_url('tools.php')));
        exit;
    }

	/**
	 * Add example hooks for common plugins (for demonstration/starter configuration).
     * IMPORTANT: These should ideally be configured via the Settings UI, not hardcoded.
	 */
	public function add_example_hooks() {
		// Example usage for WooCommerce Add to Cart Fragments
		add_filter('ajax_cacheable_actions', function ($actions) {
			// $actions[] = 'woocommerce_get_refreshed_fragments'; // Often dynamic, caching needs care
			return $actions;
		});
        /*
		add_filter('ajax_cache_key_cookies', function ($cookies, $action) {
			if ($action === 'woocommerce_get_refreshed_fragments') {
				// These cookies influence the cart fragments
				$cookies[$action][] = 'woocommerce_cart_hash';
				$cookies[$action][] = 'woocommerce_items_in_cart';
                // $cookies[$action][] = 'wp_woocommerce_session_' . COOKIEHASH; // Session cookie can vary
			}
			return $cookies;
		}, 10, 2);
        add_filter('ajax_cache_invalidate_on_post_save', function ($actions_to_invalidate, $post_id, $post_type) {
            if ($post_type === 'product') {
                // If a product changes, cart fragments might need refresh
                 $actions_to_invalidate[$post_type][] = 'woocommerce_get_refreshed_fragments';
            }
            return $actions_to_invalidate;
        }, 10, 3);
        */

		// Example: Cache a hypothetical 'get_popular_posts' AJAX action
        /*
		add_filter('ajax_cacheable_actions', function ($actions) {
			$actions[] = 'get_popular_posts_ajax';
			return $actions;
		});
        // This action might not depend on user or specific params
        add_filter('ajax_cache_per_action_expiration', function ($expirations, $action) {
			if ($action === 'get_popular_posts_ajax') {
                $expirations[$action] = HOUR_IN_SECONDS; // Cache for 1 hour
            }
			return $expirations;
		}, 10, 2);
        add_filter('ajax_cache_invalidate_on_post_save', function ($actions_to_invalidate, $post_id, $post_type) {
            if ($post_type === 'post') {
                // If any post changes, popular posts might change
                 $actions_to_invalidate[$post_type][] = 'get_popular_posts_ajax';
            }
            return $actions_to_invalidate;
        }, 10, 3);
        */
	}
} // END class Enterprise_AJAX_Cache

/**
 * Activation Hook
 */
function enterprise_ajax_cache_activate() {
	// Perform compatibility checks again on activation
	$compatible = true;
	$issues = [];

	if (version_compare(PHP_VERSION, AJAX_CACHE_MIN_PHP_VERSION, '<')) {
		$compatible = false;
		$issues[] = sprintf(__('PHP version %s+', 'enterprise-ajax-cache'), AJAX_CACHE_MIN_PHP_VERSION);
	}
	if (version_compare(get_bloginfo('version'), AJAX_CACHE_MIN_WP_VERSION, '<')) {
		$compatible = false;
		$issues[] = sprintf(__('WordPress version %s+', 'enterprise-ajax-cache'), AJAX_CACHE_MIN_WP_VERSION);
	}
	// MySQL check might be less critical here as WP already has requirements, but we can include it
	global $wpdb;
	if (!empty($wpdb)) {
		$mysql_version = $wpdb->db_version();
		if ($mysql_version && version_compare($mysql_version, AJAX_CACHE_MIN_MYSQL_VERSION, '<')) {
			$compatible = false;
			$issues[] = sprintf(__('MySQL version %s+ (Found: %s)', 'enterprise-ajax-cache'), AJAX_CACHE_MIN_MYSQL_VERSION, $mysql_version);
		}
	}

	if (!$compatible) {
		// Store issues for admin notice
		set_transient('ajax_cache_activation_error', $issues, MINUTE_IN_SECONDS * 5);

		// Prevent activation by throwing an error
		$error_message = __('Enterprise AJAX Cache could not be activated due to compatibility issues: ', 'enterprise-ajax-cache') . implode(', ', $issues);
		// Note: wp_die() might not be the best here as it can break activation process flow.
        // Relying on the transient notice might be sufficient, along with the early return in the main file.
        // However, if strict prevention is needed:
		// wp_die($error_message);
        // Alternatively, just return false or trigger_error:
        trigger_error($error_message, E_USER_ERROR);
        return;
	}

	// Add activation tasks if compatible
	add_option('ajax_cache_activated', time());
	add_option('ajax_cache_version', AJAX_CACHE_VERSION);

	// Initialize cache statistics if they don't exist
	if (get_option(AJAX_CACHE_STATS_OPTION) === false) {
        // Need the Settings class for default stats structure
        if (class_exists('Enterprise_AJAX_Cache_Settings')) {
            add_option(AJAX_CACHE_STATS_OPTION, Enterprise_AJAX_Cache_Settings::get_default_stats());
        } else {
            // Fallback if class isn't loaded yet (shouldn't happen ideally)
            add_option(AJAX_CACHE_STATS_OPTION, ['hits' => 0, 'misses' => 0, 'sets' => 0, 'purges' => 0, 'last_purge' => 0]);
        }
	}
    // Initialize log option if it doesn't exist
    if (get_option(AJAX_CACHE_LOG_OPTION) === false) {
        add_option(AJAX_CACHE_LOG_OPTION, [], '', 'no'); // Add empty array, no autoload
    }
    // Initialize settings option if it doesn't exist
    if (get_option(AJAX_CACHE_SETTINGS_KEY) === false) {
         if (class_exists('Enterprise_AJAX_Cache_Settings')) {
             add_option(AJAX_CACHE_SETTINGS_KEY, Enterprise_AJAX_Cache_Settings::get_default_settings());
         } else {
             // Fallback, less ideal as default log path calculation won't run
             add_option(AJAX_CACHE_SETTINGS_KEY, []);
         }
    }

    // Ensure the auto-purge cron is set up correctly after activation/update
    // Need to get instance *after* plugins_loaded, so this might be too early.
    // Best handled by saving settings or a separate admin_init check.
    // For now, we'll rely on admin_init hook in the main class to setup cron.
    // $instance = Enterprise_AJAX_Cache::get_instance();
    // if ($instance) {
    //     $instance->setup_auto_purge();
    // }
}
register_activation_hook(AJAX_CACHE_PLUGIN_FILE, 'enterprise_ajax_cache_activate');

/**
 * Deactivation Hook
 */
function enterprise_ajax_cache_deactivate() {
	// Clear the scheduled cron job
	wp_clear_scheduled_hook('ajax_cache_auto_purge');

	// Optionally clear all caches on deactivation (consider making this a setting?)
	// Cannot reliably get instance here as plugin might be loading/unloading.
    // If purge on deactivate is needed, might need a separate function call without instance.

    // Clear activation error transient if it exists
    delete_transient('ajax_cache_activation_error');
    delete_transient('ajax_cache_mysql_compat_error');
}
register_deactivation_hook(AJAX_CACHE_PLUGIN_FILE, 'enterprise_ajax_cache_deactivate');

/**
 * Uninstall Hook - Static context, cannot rely on instantiated class easily
 */
function enterprise_ajax_cache_uninstall() {
	global $wpdb;

	// 1. Delete Options
	delete_option('ajax_cache_activated');
	delete_option('ajax_cache_version');
	delete_option(AJAX_CACHE_STATS_OPTION);
	delete_option(AJAX_CACHE_SETTINGS_KEY);
    delete_option(AJAX_CACHE_LOG_OPTION);

	// 2. Clear Scheduled Cron
	wp_clear_scheduled_hook('ajax_cache_auto_purge');

	// 3. Delete Transients (using direct DB query for robustness)
    $transient_prefix = '_transient_' . AJAX_CACHE_TRANSIENT_PREFIX;
    $timeout_prefix = '_transient_timeout_' . AJAX_CACHE_TRANSIENT_PREFIX;
    $transient_like = $wpdb->esc_like($transient_prefix) . '%';
    $timeout_like = $wpdb->esc_like($timeout_prefix) . '%';

    $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $transient_like));
    $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $timeout_like));

    // 4. Optionally delete log file if it exists and path is known
    // Need to get the option before deleting it above.
    $settings = get_option(AJAX_CACHE_SETTINGS_KEY); // Get settings one last time
    if ($settings && !empty($settings['log_file_path']) && $settings['log_destination'] === 'file') {
       if (file_exists($settings['log_file_path']) && is_writable($settings['log_file_path'])) {
          @unlink($settings['log_file_path']);
       }
    }

    // 5. Optionally clear Redis/Memcached keys (very difficult without connection details/instance)
    // This typically requires manual cleanup or relying on TTLs.

    // Clear WP's internal cache
    wp_cache_flush();
}
register_uninstall_hook(AJAX_CACHE_PLUGIN_FILE, 'enterprise_ajax_cache_uninstall');


// ============================================================
// Initialize
// ============================================================

/**
 * Initialize the plugin main class on plugins_loaded
 */
function enterprise_ajax_cache_init() {
    // Ensure class exists before trying to get instance
    if (class_exists('Enterprise_AJAX_Cache')) {
	    $plugin = Enterprise_AJAX_Cache::get_instance();

        // Add example hooks - Comment out or remove for production, use settings UI instead.
        // $plugin->add_example_hooks();
    } else {
         // Log error if class couldn't be loaded (e.g., include file issue handled earlier)
         error_log('Enterprise AJAX Cache Error: Main plugin class "Enterprise_AJAX_Cache" not found during init.');
    }
}
add_action('plugins_loaded', 'enterprise_ajax_cache_init');


// ============================================================
// START include: includes/class-ajax-cache-logger.php
// (In a real plugin, this would be in its own file)
// ============================================================

<?php
/**
 * Logger class for Enterprise AJAX Cache
 */

// Prevent direct access
if (!defined('ABSPATH')) {
	exit;
}

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
     * @return Ajax_Cache_Logger
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
		// Initial log level can be overridden by settings later
        // $this->log_level = apply_filters('ajax_cache_log_level', self::LOG_ERROR); // Apply filter here or set via method
	}

    /**
     * Set the current logging level.
     * @param int $level Log level constant (e.g., self::LOG_INFO)
     */
    public function set_log_level(int $level) {
        if ($level >= self::LOG_NONE && $level <= self::LOG_DEBUG) {
            $this->log_level = $level;
        } else {
            $this->log_level = self::LOG_ERROR; // Default to ERROR if invalid level provided
        }
    }

    /**
     * Get the current logging level.
     * @return int
     */
    public function get_log_level() {
        return $this->log_level;
    }

	/**
	 * Log a message
     *
     * @param string $message Message to log.
     * @param int $level Log level (use constants like self::LOG_INFO).
     * @param array $context Additional data.
     * @return bool True if logged, false otherwise.
	 */
	public function log($message, $level = self::LOG_INFO, $context = array()) {
        // Bail if the level is too high for current setting or logging is off
		if ($this->log_level === self::LOG_NONE || $level > $this->log_level) {
			return false;
		}

		$level_name = self::get_level_name($level);
		$formatted_message = sprintf("[AJAX Cache] [%s] %s", $level_name, $message);

		// Basic logging to WP debug log if enabled (destination 'wp_debug' handled by custom logger)
		if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            $log_output = $formatted_message;
			if (!empty($context)) {
				// Avoid overly verbose logs in debug.log by default, customize if needed
				$log_output .= ' ' . wp_json_encode($context); // Use wp_json_encode for WP context
			}
			// We only write here if the setting isn't 'database' or 'file',
            // otherwise the custom handler will write to debug.log if needed.
            // This avoids double logging.
            $settings = get_option(AJAX_CACHE_SETTINGS_KEY, []); // Avoid calling instance methods here if possible
            $log_destination = $settings['log_destination'] ?? 'database';
            if (!in_array($log_destination, ['database', 'file'])) {
                error_log($log_output);
            }
		}

		// Trigger action for custom logging handlers (like DB or file logger)
		do_action('ajax_cache_logged', $message, $level, $context);

		return true;
	}

	/**
	 * Get the name of a log level
     * @param int $level
     * @return string
	 */
	public static function get_level_name($level) {
		switch ($level) {
            case self::LOG_NONE:
                return 'NONE';
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

	/** Log an error */
	public function error($message, $context = array()) {
		return $this->log($message, self::LOG_ERROR, $context);
	}

	/** Log a warning */
	public function warning($message, $context = array()) {
		return $this->log($message, self::LOG_WARNING, $context);
	}

	/** Log an info message */
	public function info($message, $context = array()) {
		return $this->log($message, self::LOG_INFO, $context);
	}

	/** Log a debug message */
	public function debug($message, $context = array()) {
		return $this->log($message, self::LOG_DEBUG, $context);
	}
}
?>

// ============================================================
// END include: includes/class-ajax-cache-logger.php
// ============================================================


// ============================================================
// START include: includes/class-enterprise-ajax-cache-settings.php
// (In a real plugin, this would be in its own file)
// ============================================================

<?php
/**
 * Settings class for Enterprise AJAX Cache
 */

// Prevent direct access
if (!defined('ABSPATH')) {
	exit;
}

class Enterprise_AJAX_Cache_Settings {
    /**
     * @var Enterprise_AJAX_Cache Main plugin instance
     */
    private $plugin;

    /**
     * @var array Default settings
     */
    private $defaults;

    /**
     * Constructor
     *
     * @param Enterprise_AJAX_Cache $plugin Main plugin instance
     */
    public function __construct($plugin) {
        $this->plugin = $plugin;
        $this->defaults = self::get_default_settings(); // Use static call

        // Register settings page in admin menu
        add_action('admin_menu', [$this, 'add_admin_menu']);

        // Register settings
        add_action('admin_init', [$this, 'register_settings']);

        // Handle import/export actions
        add_action('admin_post_ajax_cache_export_settings', [$this, 'export_settings']);
        add_action('admin_post_ajax_cache_import_settings', [$this, 'import_settings']);

        // Reset statistics action (handled via link nonce)
        add_action('admin_init', [$this, 'reset_statistics']);

        // Admin notices for import/export/log clearing
        add_action('admin_notices', [$this, 'admin_notices']);
    }

    /**
     * Get default settings
     *
     * @return array Default settings
     */
    public static function get_default_settings() {
        $upload_dir = wp_upload_dir();
        $default_log_path = $upload_dir['basedir'] . '/ajax-cache-logs.log';
        // Ensure the path uses correct directory separators for the OS
        $default_log_path = wp_normalize_path($default_log_path);

        return array(
            'enabled' => true,
            'debug_mode' => defined('WP_DEBUG') && WP_DEBUG, // Default based on WP_DEBUG
            'log_level' => Ajax_Cache_Logger::LOG_ERROR,
            'log_destination' => 'database', // Default to database for easier viewing initially
            'log_file_path' => $default_log_path, // Default log file path
            'log_max_entries' => 1000, // Max entries for DB logging
            'cache_backend' => 'transients', // Default backend
            'redis_settings' => array(
                'host' => '127.0.0.1',
                'port' => 6379,
                'auth' => '',
                'database' => 0,
            ),
            'memcached_settings' => array(
                'host' => '127.0.0.1',
                'port' => 11211,
            ),
            'default_expiration' => HOUR_IN_SECONDS, // 1 hour default TTL
            'per_action_expiration' => array(), // Action => TTL (seconds)
            'cacheable_actions' => array(), // List of action names
            'cache_key_params' => array(), // Action => [param1, param2]
            'cache_key_factors' => array(
                'user_id' => false,
                'user_roles' => false,
            ),
            'cache_key_cookies' => array(), // Action => [cookie1, cookie2]
            'watched_post_types' => array('post', 'page'), // Post types triggering invalidation
            'invalidation_rules' => array(), // post_type => [action1, action2]
            'auto_purge_schedule' => 'never', // Cron schedule ('never', 'hourly', 'twicedaily', 'daily', 'weekly')
        );
    }

     /**
      * Get default cache statistics structure.
      * @return array
      */
     public static function get_default_stats() {
         return array(
             'hits' => 0,
             'misses' => 0,
             'sets' => 0,
             'purges' => 0,
             'last_purge' => 0
         );
     }

    /**
     * Get plugin settings, merging with defaults.
     *
     * @return array Plugin settings
     */
    public function get_settings() {
        $settings = get_option(AJAX_CACHE_SETTINGS_KEY, array());
        // Ensure nested array defaults are properly merged
        $defaults = self::get_default_settings();
        $settings = array_replace_recursive($defaults, $settings);
        // wp_parse_args is not recursive, array_replace_recursive is better here.

        // Re-apply top-level defaults for keys that might be missing after recursive merge
        // (e.g., if a top-level key was removed entirely)
        $settings = wp_parse_args($settings, $defaults);

        return $settings;
    }

    /**
     * Register the plugin settings page under Tools menu.
     */
    public function add_admin_menu() {
        add_management_page(
            __('Enterprise AJAX Cache Settings', 'enterprise-ajax-cache'), // Page Title
            __('AJAX Cache', 'enterprise-ajax-cache'), // Menu Title
            'manage_options', // Capability required
            'enterprise-ajax-cache', // Menu slug
            [$this, 'render_settings_page'] // Callback function
        );
    }

    /**
     * Register settings, sections, and fields using WordPress Settings API.
     */
    public function register_settings() {
        register_setting(
            'ajax_cache_settings_group',        // Option group (used in settings_fields())
            AJAX_CACHE_SETTINGS_KEY,            // Option name in wp_options table
            [$this, 'sanitize_settings']        // Sanitize callback function
        );

        // SECTION: General Settings
        add_settings_section(
            'ajax_cache_general_section',
            __('General Settings', 'enterprise-ajax-cache'),
            [$this, 'general_section_callback'],
            'enterprise_ajax_cache_page' // Page slug where this section appears
        );
        add_settings_field('enabled', __('Enable Caching', 'enterprise-ajax-cache'), [$this, 'enabled_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_general_section');
        add_settings_field('debug_mode', __('Debug Mode', 'enterprise-ajax-cache'), [$this, 'debug_mode_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_general_section');

        // SECTION: Logging Settings
        add_settings_section('ajax_cache_logging_section', __('Logging Settings', 'enterprise-ajax-cache'), [$this, 'logging_section_callback'], 'enterprise_ajax_cache_page');
        add_settings_field('log_level', __('Log Level', 'enterprise-ajax-cache'), [$this, 'log_level_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_logging_section');
        add_settings_field('log_destination', __('Log Destination', 'enterprise-ajax-cache'), [$this, 'log_destination_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_logging_section');
        add_settings_field('log_file_path', __('Log File Path', 'enterprise-ajax-cache'), [$this, 'log_file_path_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_logging_section');
        add_settings_field('log_max_entries', __('Max DB Log Entries', 'enterprise-ajax-cache'), [$this, 'log_max_entries_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_logging_section');

        // SECTION: Cache Storage
        add_settings_section('ajax_cache_storage_section', __('Cache Storage', 'enterprise-ajax-cache'), [$this, 'storage_section_callback'], 'enterprise_ajax_cache_page');
        add_settings_field('cache_backend', __('Cache Backend', 'enterprise-ajax-cache'), [$this, 'backend_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_storage_section');
        add_settings_field('redis_settings', __('Redis Settings', 'enterprise-ajax-cache'), [$this, 'redis_settings_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_storage_section');
        add_settings_field('memcached_settings', __('Memcached Settings', 'enterprise-ajax-cache'), [$this, 'memcached_settings_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_storage_section');

        // SECTION: Cache Actions & Expiration
        add_settings_section('ajax_cache_actions_section', __('Cacheable Actions & Expiration', 'enterprise-ajax-cache'), [$this, 'actions_section_callback'], 'enterprise_ajax_cache_page');
        add_settings_field('default_expiration', __('Default Expiration', 'enterprise-ajax-cache'), [$this, 'default_expiration_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_actions_section');
        add_settings_field('cacheable_actions', __('Cacheable AJAX Actions', 'enterprise-ajax-cache'), [$this, 'cacheable_actions_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_actions_section');
        add_settings_field('per_action_expiration', __('Per-Action Expiration', 'enterprise-ajax-cache'), [$this, 'per_action_expiration_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_actions_section');

        // SECTION: Cache Key Configuration
        add_settings_section('ajax_cache_key_section', __('Cache Key Configuration', 'enterprise-ajax-cache'), [$this, 'key_section_callback'], 'enterprise_ajax_cache_page');
        add_settings_field('cache_key_factors', __('Global Key Factors', 'enterprise-ajax-cache'), [$this, 'key_factors_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_key_section');
        add_settings_field('cache_key_params', __('Per-Action Request Parameters', 'enterprise-ajax-cache'), [$this, 'key_params_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_key_section');
        add_settings_field('cache_key_cookies', __('Per-Action Cookies', 'enterprise-ajax-cache'), [$this, 'key_cookies_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_key_section');

        // SECTION: Cache Invalidation
        add_settings_section('ajax_cache_invalidation_section', __('Cache Invalidation', 'enterprise-ajax-cache'), [$this, 'invalidation_section_callback'], 'enterprise_ajax_cache_page');
        add_settings_field('watched_post_types', __('Watched Post Types', 'enterprise-ajax-cache'), [$this, 'watched_post_types_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_invalidation_section');
        add_settings_field('invalidation_rules', __('Invalidation Rules', 'enterprise-ajax-cache'), [$this, 'invalidation_rules_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_invalidation_section');
        add_settings_field('auto_purge_schedule', __('Automatic Purge Schedule', 'enterprise-ajax-cache'), [$this, 'auto_purge_schedule_callback'], 'enterprise_ajax_cache_page', 'ajax_cache_invalidation_section');
    }

    /**
     * Sanitize settings input before saving to database.
     *
     * @param array $input Raw input data from $_POST.
     * @return array Sanitized settings.
     */
    public function sanitize_settings($input) {
        $sanitized = array();
        $defaults = self::get_default_settings(); // Get defaults for comparison and fallback

        // Ensure input is an array
        if (!is_array($input)) {
            $input = [];
             add_settings_error(AJAX_CACHE_SETTINGS_KEY, 'invalid_input', __('Settings input was not an array. Reverted to defaults.', 'enterprise-ajax-cache'), 'error');
             return $defaults;
        }

        // General Settings
        $sanitized['enabled'] = isset($input['enabled']) ? true : false; // Checkbox value
        $sanitized['debug_mode'] = isset($input['debug_mode']) ? true : false; // Checkbox value

        // Logging Settings
        $log_level = isset($input['log_level']) ? intval($input['log_level']) : $defaults['log_level'];
        $sanitized['log_level'] = in_array($log_level, array_keys($this->get_log_level_options())) ? $log_level : $defaults['log_level'];

        $log_destination = isset($input['log_destination']) ? sanitize_key($input['log_destination']) : $defaults['log_destination'];
        $sanitized['log_destination'] = in_array($log_destination, array_keys($this->get_log_destination_options())) ? $log_destination : $defaults['log_destination'];

        // Sanitize log file path carefully
        $log_file_path = isset($input['log_file_path']) ? trim($input['log_file_path']) : $defaults['log_file_path'];
        if (!empty($log_file_path)) {
            // Normalize path, basic validation (is it absolute? does it contain '../'?)
            $log_file_path = wp_normalize_path($log_file_path);
            // Very basic security: disallow relative paths trying to go up
            if (strpos($log_file_path, '../') === false) {
                 // Check if it's within a reasonable directory (e.g., WP_CONTENT_DIR) or is absolute
                 if (strpos($log_file_path, WP_CONTENT_DIR) === 0 || (DIRECTORY_SEPARATOR === '/' && strpos($log_file_path, '/') === 0) || (DIRECTORY_SEPARATOR === '\\' && preg_match('/^[a-zA-Z]:\\\/', $log_file_path))) {
                      $sanitized['log_file_path'] = $log_file_path;
                 } else {
                      $sanitized['log_file_path'] = $defaults['log_file_path']; // Revert if suspicious
                      add_settings_error(AJAX_CACHE_SETTINGS_KEY, 'invalid_log_path', __('Invalid log file path provided. Reverted to default.', 'enterprise-ajax-cache'), 'warning');
                 }
            } else {
                $sanitized['log_file_path'] = $defaults['log_file_path']; // Revert if suspicious
                 add_settings_error(AJAX_CACHE_SETTINGS_KEY, 'invalid_log_path_relative', __('Log file path cannot contain "../". Reverted to default.', 'enterprise-ajax-cache'), 'warning');
            }
        } else {
            $sanitized['log_file_path'] = $defaults['log_file_path']; // Revert to default if empty
        }


        $sanitized['log_max_entries'] = isset($input['log_max_entries']) ? absint($input['log_max_entries']) : $defaults['log_max_entries'];
        $sanitized['log_max_entries'] = max(10, $sanitized['log_max_entries']); // Minimum 10

        // Cache Storage Settings
        $cache_backend = isset($input['cache_backend']) ? sanitize_key($input['cache_backend']) : $defaults['cache_backend'];
        $sanitized['cache_backend'] = in_array($cache_backend, array_keys($this->get_backend_options())) ? $cache_backend : $defaults['cache_backend'];

        // Sanitize Redis settings
        $sanitized['redis_settings'] = $defaults['redis_settings'];
        if (isset($input['redis_settings']) && is_array($input['redis_settings'])) {
            $sanitized['redis_settings']['host'] = isset($input['redis_settings']['host']) ? sanitize_text_field($input['redis_settings']['host']) : $defaults['redis_settings']['host'];
            $sanitized['redis_settings']['port'] = isset($input['redis_settings']['port']) ? absint($input['redis_settings']['port']) : $defaults['redis_settings']['port'];
            $sanitized['redis_settings']['auth'] = isset($input['redis_settings']['auth']) ? sanitize_text_field($input['redis_settings']['auth']) : $defaults['redis_settings']['auth']; // Keep password as text
            $sanitized['redis_settings']['database'] = isset($input['redis_settings']['database']) ? absint($input['redis_settings']['database']) : $defaults['redis_settings']['database'];
        }

        // Sanitize Memcached settings
        $sanitized['memcached_settings'] = $defaults['memcached_settings'];
        if (isset($input['memcached_settings']) && is_array($input['memcached_settings'])) {
            $sanitized['memcached_settings']['host'] = isset($input['memcached_settings']['host']) ? sanitize_text_field($input['memcached_settings']['host']) : $defaults['memcached_settings']['host'];
            $sanitized['memcached_settings']['port'] = isset($input['memcached_settings']['port']) ? absint($input['memcached_settings']['port']) : $defaults['memcached_settings']['port'];
        }

        // Cache Expiration Settings
        $sanitized['default_expiration'] = isset($input['default_expiration']) ? absint($input['default_expiration']) : $defaults['default_expiration'];
        $sanitized['default_expiration'] = max(1, $sanitized['default_expiration']); // Minimum 1 second

        // Per-Action Expiration (key = action, value = expiration)
        $sanitized['per_action_expiration'] = array();
        if (isset($input['per_action_expiration']) && is_array($input['per_action_expiration'])) {
            foreach ($input['per_action_expiration'] as $action => $expiration) {
                $sane_action = sanitize_key($action);
                $sane_expiration = intval($expiration); // Use intval, allows negative which might mean something? Let's use absint.
                $sane_expiration = ($expiration === '' || $expiration === null) ? null : absint($expiration); // Allow blank to mean 'use default'

                if (!empty($sane_action)) {
                    if ($sane_expiration === null) {
                        // If explicitly blanked, remove the setting for this action
                        unset($sanitized['per_action_expiration'][$sane_action]);
                    } elseif ($sane_expiration >= 0) { // Allow 0 for non-expiring
                         $sanitized['per_action_expiration'][$sane_action] = $sane_expiration;
                    }
                }
            }
        }

        // Cacheable Actions (simple array of action names)
        $sanitized['cacheable_actions'] = array();
        if (isset($input['cacheable_actions']) && is_array($input['cacheable_actions'])) {
            foreach ($input['cacheable_actions'] as $action) {
                $sane_action = sanitize_key($action);
                if (!empty($sane_action)) {
                    $sanitized['cacheable_actions'][] = $sane_action;
                }
            }
            $sanitized['cacheable_actions'] = array_unique($sanitized['cacheable_actions']); // Ensure unique
            sort($sanitized['cacheable_actions']); // Keep sorted for consistency
        }

        // Cache Key Settings
        // Global Factors (user_id, user_roles)
        $sanitized['cache_key_factors'] = $defaults['cache_key_factors'];
        if (isset($input['cache_key_factors']) && is_array($input['cache_key_factors'])) {
             $sanitized['cache_key_factors']['user_id'] = isset($input['cache_key_factors']['user_id']);
             $sanitized['cache_key_factors']['user_roles'] = isset($input['cache_key_factors']['user_roles']);
        }

        // Per-Action Parameters (action => [param1, param2])
        $sanitized['cache_key_params'] = array();
        if (isset($input['cache_key_params']) && is_array($input['cache_key_params'])) {
            foreach ($input['cache_key_params'] as $action => $params) {
                $sane_action = sanitize_key($action);
                // Only process if action is still in the cacheable list
                if (!empty($sane_action) && in_array($sane_action, $sanitized['cacheable_actions']) && is_array($params)) {
                    $sane_params = [];
                    foreach ($params as $param) {
                        $sane_param = sanitize_key($param); // Params are usually keys
                        if (!empty($sane_param)) {
                            $sane_params[] = $sane_param;
                        }
                    }
                    if (!empty($sane_params)) {
                         $sanitized['cache_key_params'][$sane_action] = array_unique($sane_params);
                         sort($sanitized['cache_key_params'][$sane_action]); // Keep sorted
                    }
                }
            }
        }

        // Per-Action Cookies (action => [cookie1, cookie2])
        $sanitized['cache_key_cookies'] = array();
        if (isset($input['cache_key_cookies']) && is_array($input['cache_key_cookies'])) {
            foreach ($input['cache_key_cookies'] as $action => $cookies) {
                $sane_action = sanitize_key($action);
                 // Only process if action is still in the cacheable list
                if (!empty($sane_action) && in_array($sane_action, $sanitized['cacheable_actions']) && is_array($cookies)) {
                    $sane_cookies = [];
                    foreach ($cookies as $cookie) {
                        // Cookie names can have more characters than keys, use sanitize_text_field but remove spaces?
                        // Or stick to sanitize_key if simple names are expected. Let's use sanitize_key for consistency.
                        $sane_cookie = sanitize_key($cookie); // Maybe too restrictive? Consider sanitize_text_field?
                        // Let's allow more chars but basic sanitization
                        $sane_cookie = sanitize_text_field($cookie);
                        $sane_cookie = preg_replace('/[^a-zA-Z0-9_\-\.%]/', '', $sane_cookie); // Allow common cookie chars

                        if (!empty($sane_cookie)) {
                            $sane_cookies[] = $sane_cookie;
                        }
                    }
                     if (!empty($sane_cookies)) {
                         $sanitized['cache_key_cookies'][$sane_action] = array_unique($sane_cookies);
                         sort($sanitized['cache_key_cookies'][$sane_action]); // Keep sorted
                     }
                }
            }
        }


        // Cache Invalidation Settings
        // Watched Post Types (simple array of post type names)
        $sanitized['watched_post_types'] = array();
        if (isset($input['watched_post_types']) && is_array($input['watched_post_types'])) {
            $all_post_types = get_post_types([], 'names'); // Get all registered types
            foreach ($input['watched_post_types'] as $post_type) {
                $sane_type = sanitize_key($post_type);
                if (!empty($sane_type) && post_type_exists($sane_type)) { // Validate against existing types
                    $sanitized['watched_post_types'][] = $sane_type;
                }
            }
            $sanitized['watched_post_types'] = array_unique($sanitized['watched_post_types']);
            sort($sanitized['watched_post_types']); // Keep sorted
        }

        // Invalidation Rules (post_type => [action1, action2])
        $sanitized['invalidation_rules'] = array();
        if (isset($input['invalidation_rules']) && is_array($input['invalidation_rules'])) {
            // Use the sanitized list of cacheable actions and watched post types for validation
            $valid_actions = $sanitized['cacheable_actions'];
            $valid_types = $sanitized['watched_post_types'];

            foreach ($input['invalidation_rules'] as $post_type => $actions) {
                $sane_type = sanitize_key($post_type);
                // Only process if post type is still in the watched list
                if (!empty($sane_type) && in_array($sane_type, $valid_types) && is_array($actions)) {
                    $sane_actions = [];
                    foreach ($actions as $action) {
                        $sane_action = sanitize_key($action);
                        // Only add if action is still in the cacheable list
                        if (!empty($sane_action) && in_array($sane_action, $valid_actions)) {
                            $sane_actions[] = $sane_action;
                        }
                    }
                    if (!empty($sane_actions)) {
                        $sanitized['invalidation_rules'][$sane_type] = array_unique($sane_actions);
                        sort($sanitized['invalidation_rules'][$sane_type]); // Keep sorted
                    }
                }
            }
        }

        // Auto Purge Schedule
        $auto_purge_schedule = isset($input['auto_purge_schedule']) ? sanitize_key($input['auto_purge_schedule']) : $defaults['auto_purge_schedule'];
        $sanitized['auto_purge_schedule'] = array_key_exists($auto_purge_schedule, $this->get_schedule_options()) ? $auto_purge_schedule : $defaults['auto_purge_schedule'];

        // Trigger actions after settings are saved (e.g., reload settings in main class, update cron)
        do_action('ajax_cache_settings_saved', $sanitized, $input);

        // Important: Reload settings in the main plugin instance immediately AFTER saving
        // and before rescheduling cron which depends on the new settings.
        if ($this->plugin instanceof Enterprise_AJAX_Cache) {
            $this->plugin->reload_settings();
            $this->plugin->setup_auto_purge();
        } else {
             add_settings_error(AJAX_CACHE_SETTINGS_KEY, 'plugin_instance_error', __('Error: Could not access main plugin instance after saving settings.', 'enterprise-ajax-cache'), 'error');
        }


        return $sanitized;
    }

    // --- Section Callbacks ---
    public function general_section_callback() { echo '<p>' . esc_html__('Configure general plugin behavior.', 'enterprise-ajax-cache') . '</p>'; }
    public function logging_section_callback() { echo '<p>' . esc_html__('Configure logging behavior and storage.', 'enterprise-ajax-cache') . '</p>'; }
    public function storage_section_callback() { echo '<p>' . esc_html__('Configure where cached data is stored.', 'enterprise-ajax-cache') . '</p>'; }
    public function actions_section_callback() { echo '<p>' . esc_html__('Define which AJAX actions are cacheable and their lifespan.', 'enterprise-ajax-cache') . '</p>'; }
    public function key_section_callback() { echo '<p>' . esc_html__('Define how unique cache keys are generated based on request context.', 'enterprise-ajax-cache') . '</p>'; }
    public function invalidation_section_callback() { echo '<p>' . esc_html__('Configure automatic cache clearing based on events.', 'enterprise-ajax-cache') . '</p>'; }

    // --- Field Callbacks ---

    // General
    public function enabled_callback() {
        $settings = $this->get_settings();
        ?>
        <label>
            <input type="checkbox" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[enabled]" value="1" <?php checked(1, $settings['enabled']); ?>/>
            <?php esc_html_e('Enable AJAX caching functionality', 'enterprise-ajax-cache'); ?>
        </label>
        <p class="description"><?php esc_html_e('Globally enable or disable the caching mechanism.', 'enterprise-ajax-cache'); ?></p>
        <?php
    }

    public function debug_mode_callback() {
        $settings = $this->get_settings();
        ?>
        <label>
            <input type="checkbox" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[debug_mode]" value="1" <?php checked(1, $settings['debug_mode']); ?>/>
            <?php esc_html_e('Enable Debug Mode', 'enterprise-ajax-cache'); ?>
        </label>
        <p class="description"><?php esc_html_e('Adds debug headers (X-AJAX-Cache-*) to AJAX responses and may increase logging verbosity.', 'enterprise-ajax-cache'); ?></p>
        <?php
    }

    // Logging Helpers
    private function get_log_level_options() {
        return array(
            Ajax_Cache_Logger::LOG_NONE => __('None (Disabled)', 'enterprise-ajax-cache'),
            Ajax_Cache_Logger::LOG_ERROR => __('Errors Only', 'enterprise-ajax-cache'),
            Ajax_Cache_Logger::LOG_WARNING => __('Warnings & Errors', 'enterprise-ajax-cache'),
            Ajax_Cache_Logger::LOG_INFO => __('Info, Warnings & Errors', 'enterprise-ajax-cache'),
            Ajax_Cache_Logger::LOG_DEBUG => __('Debug (All Messages)', 'enterprise-ajax-cache'),
        );
    }
    private function get_log_destination_options() {
         return array(
             'database' => __('Database (View below)', 'enterprise-ajax-cache'),
             'file' => __('Custom Log File', 'enterprise-ajax-cache'),
             'wp_debug' => __('WordPress Debug Log (debug.log)', 'enterprise-ajax-cache'),
         );
    }

    // Logging Fields
    public function log_level_callback() {
        $settings = $this->get_settings();
        $levels = $this->get_log_level_options();
        ?>
        <select name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[log_level]">
            <?php foreach ($levels as $level => $label) : ?>
                <option value="<?php echo esc_attr($level); ?>" <?php selected($level, $settings['log_level']); ?>>
                    <?php echo esc_html($label); ?>
                </option>
            <?php endforeach; ?>
        </select>
        <p class="description"><?php esc_html_e('Select the minimum level of messages to log. Higher levels include lower levels.', 'enterprise-ajax-cache'); ?></p>
        <?php
    }

    public function log_destination_callback() {
        $settings = $this->get_settings();
        $destinations = $this->get_log_destination_options();
        ?>
        <select name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[log_destination]" id="ajax_cache_log_destination">
            <?php foreach ($destinations as $dest => $label) : ?>
                <option value="<?php echo esc_attr($dest); ?>" <?php selected($dest, $settings['log_destination']); ?>>
                    <?php echo esc_html($label); ?>
                </option>
            <?php endforeach; ?>
        </select>
        <p class="description">
             <?php esc_html_e('Where log entries should be stored.', 'enterprise-ajax-cache'); ?>
             <span class="log-dest-desc log-dest-desc-database" style="<?php echo $settings['log_destination'] === 'database' ? '' : 'display:none;'; ?>"><?php esc_html_e('Logs stored in WP options table.', 'enterprise-ajax-cache'); ?></span>
             <span class="log-dest-desc log-dest-desc-file" style="<?php echo $settings['log_destination'] === 'file' ? '' : 'display:none;'; ?>"><?php esc_html_e('Requires a writable path below.', 'enterprise-ajax-cache'); ?></span>
             <span class="log-dest-desc log-dest-desc-wp_debug" style="<?php echo $settings['log_destination'] === 'wp_debug' ? '' : 'display:none;'; ?>">
                 <?php printf(
                     wp_kses(__('Requires %1$s and %2$s to be enabled in %3$s.', 'enterprise-ajax-cache'), ['code' => []]),
                     '<code>WP_DEBUG</code>', '<code>WP_DEBUG_LOG</code>', '<code>wp-config.php</code>'
                 ); ?>
             </span>
        </p>
        <?php
    }

    public function log_file_path_callback() {
        $settings = $this->get_settings();
        ?>
        <div id="log_file_path_container" style="<?php echo $settings['log_destination'] === 'file' ? '' : 'display: none;'; ?>">
            <input type="text" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[log_file_path]" value="<?php echo esc_attr($settings['log_file_path']); ?>" class="regular-text" />
            <p class="description"><?php esc_html_e('Absolute path to the log file. Ensure the directory is writable by the web server.', 'enterprise-ajax-cache'); ?></p>
        </div>

        <script type="text/javascript">
            jQuery(document).ready(function($) {
                function toggleLogPathField() {
                    var selectedDest = $('#ajax_cache_log_destination').val();
                    $('#log_file_path_container').toggle(selectedDest === 'file');
                    $('#log_max_entries_container').toggle(selectedDest === 'database'); // Also toggle max entries here
                    $('.log-dest-desc').hide();
                    $('.log-dest-desc-' + selectedDest).show();
                }
                $('#ajax_cache_log_destination').on('change', toggleLogPathField);
                // Initial call
                toggleLogPathField();
            });
        </script>
        <?php
    }

    public function log_max_entries_callback() {
        $settings = $this->get_settings();
        ?>
         <div id="log_max_entries_container" style="<?php echo $settings['log_destination'] === 'database' ? '' : 'display: none;'; ?>">
            <input type="number" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[log_max_entries]" value="<?php echo esc_attr($settings['log_max_entries']); ?>" min="10" step="10" class="small-text" />
            <p class="description"><?php esc_html_e('Maximum number of log entries to keep when using Database logging.', 'enterprise-ajax-cache'); ?></p>
        </div>
        <?php // Script to toggle visibility moved to log_file_path_callback for simplicity ?>
        <?php
    }

    // Storage Helpers
    private function get_backend_options() {
        // Check which backends are available/potentially usable
        $options = [];
        $options['transients'] = __('WordPress Transients (Database default)', 'enterprise-ajax-cache');

        // Check for Redis (e.g., via Redis Object Cache plugin or similar PHP extension)
        $redis_available = (class_exists('Redis') && function_exists('wp_redis_get_info')) || (defined('WP_REDIS_VERSION') && function_exists('wp_redis_instance'));
        if ($redis_available) {
            $options['redis'] = __('Redis', 'enterprise-ajax-cache');
        } else {
            $options['redis'] = __('Redis (Requires compatible plugin or setup)', 'enterprise-ajax-cache');
        }

        // Check for Memcached (e.g., via Memcached Object Cache plugin or similar PHP extension)
        $memcached_available = (class_exists('Memcached') || class_exists('Memcache')); // Check extension existence first
        if ($memcached_available && wp_using_ext_object_cache()) { // Then check if WP is using an external cache
            // Further check if the object cache *looks* like Memcached
             $is_memcached = false;
             if (isset($GLOBALS['wp_object_cache']) && is_object($GLOBALS['wp_object_cache'])) {
                  $cache_class = get_class($GLOBALS['wp_object_cache']);
                  if (stripos($cache_class, 'Memcached') !== false) $is_memcached = true;
                  // Some object cache plugins add a specific property or method
                  if (property_exists($GLOBALS['wp_object_cache'], 'is_memcached')) {
                        $is_memcached = $GLOBALS['wp_object_cache']->is_memcached;
                  } elseif (method_exists($GLOBALS['wp_object_cache'], 'get_mc')) { // Common method name in Memcached plugins
                        $is_memcached = true;
                  }
             }
             if ($is_memcached) {
                $options['memcached'] = __('Memcached (Active Object Cache)', 'enterprise-ajax-cache');
             } else {
                 $options['memcached'] = __('Memcached (External Object Cache detected, but may not be Memcached)', 'enterprise-ajax-cache');
             }
        } else {
             $options['memcached'] = __('Memcached (Requires compatible plugin or setup)', 'enterprise-ajax-cache');
        }

        return $options;
    }

    // Storage Fields
    public function backend_callback() {
        $settings = $this->get_settings();
        $backends = $this->get_backend_options();
        $redis_available = (class_exists('Redis') && function_exists('wp_redis_get_info')) || defined('WP_REDIS_VERSION');
        $memcached_available = (class_exists('Memcached') || class_exists('Memcache'));

        ?>
        <select name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[cache_backend]" id="ajax_cache_backend">
            <?php foreach ($backends as $value => $label) :
                 // Disable selection if backend extension/plugin seems missing
                 $disabled = (($value === 'redis' && !$redis_available) || ($value === 'memcached' && !$memcached_available));
                ?>
                <option value="<?php echo esc_attr($value); ?>" <?php selected($value, $settings['cache_backend']); ?> <?php disabled($disabled); ?>>
                    <?php echo esc_html($label); ?>
                </option>
            <?php endforeach; ?>
        </select>
        <p class="description">
            <?php esc_html_e('Select the storage backend. External backends (Redis/Memcached) require server setup and potentially another WP plugin.', 'enterprise-ajax-cache'); ?>
            <?php if (wp_using_ext_object_cache() && $settings['cache_backend'] === 'transients'): ?>
                <br><strong><?php esc_html_e('Note:', 'enterprise-ajax-cache'); ?></strong> <?php esc_html_e('An external object cache is active. Choosing "Transients" might use that object cache instead of the database.', 'enterprise-ajax-cache'); ?>
            <?php endif; ?>
        </p>
         <?php
    }

    public function redis_settings_callback() {
        $settings = $this->get_settings();
        $redis_settings = $settings['redis_settings'];
        $current_backend = $settings['cache_backend'];
        ?>
        <div id="redis_settings_container" class="backend-settings" style="<?php echo $current_backend === 'redis' ? '' : 'display:none;'; ?>">
            <p class="description"><?php esc_html_e('These settings might be ignored if using a Redis Object Cache plugin that uses constants in wp-config.php.', 'enterprise-ajax-cache'); ?></p>
            <table class="form-table" style="width: auto; margin-top: 0;">
                <tbody>
                <tr>
                    <th scope="row"><label for="redis_host"><?php esc_html_e('Host', 'enterprise-ajax-cache'); ?></label></th>
                    <td><input id="redis_host" type="text" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[redis_settings][host]" value="<?php echo esc_attr($redis_settings['host']); ?>" class="regular-text" /></td>
                </tr>
                <tr>
                    <th scope="row"><label for="redis_port"><?php esc_html_e('Port', 'enterprise-ajax-cache'); ?></label></th>
                    <td><input id="redis_port" type="number" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[redis_settings][port]" value="<?php echo esc_attr($redis_settings['port']); ?>" class="small-text" /></td>
                </tr>
                <tr>
                    <th scope="row"><label for="redis_auth"><?php esc_html_e('Password', 'enterprise-ajax-cache'); ?></label></th>
                    <td><input id="redis_auth" type="password" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[redis_settings][auth]" value="<?php echo esc_attr($redis_settings['auth']); ?>" class="regular-text" placeholder="<?php esc_attr_e('(Optional)', 'enterprise-ajax-cache'); ?>"/></td>
                </tr>
                <tr>
                    <th scope="row"><label for="redis_database"><?php esc_html_e('Database', 'enterprise-ajax-cache'); ?></label></th>
                    <td><input id="redis_database" type="number" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[redis_settings][database]" value="<?php echo esc_attr($redis_settings['database']); ?>" min="0" class="small-text" /></td>
                </tr>
                </tbody>
            </table>
        </div>
        <?php
    }

    public function memcached_settings_callback() {
        $settings = $this->get_settings();
        $memcached_settings = $settings['memcached_settings'];
        $current_backend = $settings['cache_backend'];
        ?>
        <div id="memcached_settings_container" class="backend-settings" style="<?php echo $current_backend === 'memcached' ? '' : 'display:none;'; ?>">
             <p class="description"><?php esc_html_e('These settings might be ignored if using a Memcached Object Cache plugin that uses constants in wp-config.php.', 'enterprise-ajax-cache'); ?></p>
            <table class="form-table" style="width: auto; margin-top: 0;">
                 <tbody>
                <tr>
                    <th scope="row"><label for="memcached_host"><?php esc_html_e('Host', 'enterprise-ajax-cache'); ?></label></th>
                    <td><input id="memcached_host" type="text" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[memcached_settings][host]" value="<?php echo esc_attr($memcached_settings['host']); ?>" class="regular-text" /></td>
                </tr>
                <tr>
                    <th scope="row"><label for="memcached_port"><?php esc_html_e('Port', 'enterprise-ajax-cache'); ?></label></th>
                    <td><input id="memcached_port" type="number" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[memcached_settings][port]" value="<?php echo esc_attr($memcached_settings['port']); ?>" class="small-text" /></td>
                </tr>
                 </tbody>
            </table>
        </div>

        <script type="text/javascript">
            jQuery(document).ready(function($) {
                function toggleBackendSettings() {
                    var backend = $('#ajax_cache_backend').val();
                    $('.backend-settings').hide(); // Hide all backend settings divs
                    $('#' + backend + '_settings_container').show(); // Show the selected one
                }
                $('#ajax_cache_backend').on('change', toggleBackendSettings);
                 // Initial call on page load
                 toggleBackendSettings();
            });
        </script>
        <?php
    }

    // Actions & Expiration Fields
    public function default_expiration_callback() {
        $settings = $this->get_settings();
        $expiration = $settings['default_expiration'];
        ?>
        <input type="number" id="default_expiration_input" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[default_expiration]" value="<?php echo esc_attr($expiration); ?>" min="1" step="1" class="small-text" />
        <?php esc_html_e('seconds', 'enterprise-ajax-cache'); ?>
        <p class="description">
             <?php esc_html_e('Default time until cached responses expire. Minimum 1 second.', 'enterprise-ajax-cache'); ?>
             <br><?php esc_html_e('Common values:', 'enterprise-ajax-cache'); ?>
             <a href="#" class="exp-preset" data-val="<?php echo esc_attr(MINUTE_IN_SECONDS); ?>"><?php esc_html_e('1 min', 'enterprise-ajax-cache'); ?></a> |
             <a href="#" class="exp-preset" data-val="<?php echo esc_attr(MINUTE_IN_SECONDS * 5); ?>"><?php esc_html_e('5 min', 'enterprise-ajax-cache'); ?></a> |
             <a href="#" class="exp-preset" data-val="<?php echo esc_attr(MINUTE_IN_SECONDS * 15); ?>"><?php esc_html_e('15 min', 'enterprise-ajax-cache'); ?></a> |
             <a href="#" class="exp-preset" data-val="<?php echo esc_attr(HOUR_IN_SECONDS); ?>"><?php esc_html_e('1 hour', 'enterprise-ajax-cache'); ?></a> |
             <a href="#" class="exp-preset" data-val="<?php echo esc_attr(DAY_IN_SECONDS); ?>"><?php esc_html_e('1 day', 'enterprise-ajax-cache'); ?></a> |
              <a href="#" class="exp-preset" data-val="0"><?php esc_html_e('0 (Non-expiring - if supported)', 'enterprise-ajax-cache'); ?></a>
        </p>
        <script type="text/javascript">
            jQuery(document).ready(function($) {
                // Use event delegation in case the field is dynamically added/removed
                $(document).on('click', '.exp-preset', function(e) {
                    e.preventDefault();
                    $('#default_expiration_input').val($(this).data('val')).trigger('change'); // Trigger change for potential listeners
                });
            });
        </script>
        <?php
    }

    public function cacheable_actions_callback() {
        $settings = $this->get_settings();
        $cacheable_actions = $settings['cacheable_actions'];
        $all_ajax_actions = $this->get_registered_ajax_actions(); // Fetch potential actions
        ?>
        <div id="cacheable-actions-list">
            <p class="description"><?php esc_html_e('List the AJAX action names (from $_REQUEST["action"]) that should be cached.', 'enterprise-ajax-cache'); ?></p>
             <table class="wp-list-table widefat striped" style="width: auto; max-width: 600px;">
                <thead>
                    <tr>
                        <th style="width:80%;"><?php esc_html_e('Action Name', 'enterprise-ajax-cache'); ?></th>
                        <th style="width:20%;"><?php esc_html_e('Remove', 'enterprise-ajax-cache'); ?></th>
                    </tr>
                </thead>
                <tbody id="cacheable-actions-tbody">
                    <?php if (!empty($cacheable_actions)) : ?>
                        <?php foreach ($cacheable_actions as $action) : ?>
                            <tr data-action="<?php echo esc_attr($action); ?>">
                                <td>
                                    <input type="hidden" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[cacheable_actions][]" value="<?php echo esc_attr($action); ?>" />
                                    <?php echo esc_html($action); ?>
                                </td>
                                <td>
                                    <button type="button" class="button button-small remove-cacheable-action" title="<?php esc_attr_e('Remove Action', 'enterprise-ajax-cache'); ?>">
                                        <span class="dashicons dashicons-trash"></span>
                                    </button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else : ?>
                        <tr class="no-items">
                            <td colspan="2"><em><?php esc_html_e('No actions configured yet.', 'enterprise-ajax-cache'); ?></em></td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <div id="add-cacheable-action-ui" style="margin-top: 15px;">
             <h4><?php esc_html_e('Add Action', 'enterprise-ajax-cache'); ?></h4>
             <select id="new_ajax_action_select" style="width: 300px; max-width: 100%;">
                 <option value="">-- <?php esc_html_e('Select common action or enter manually', 'enterprise-ajax-cache'); ?> --</option>
                 <?php foreach ($all_ajax_actions as $action) : ?>
                     <?php if (!in_array($action, $cacheable_actions)) : // Only show actions not already added ?>
                        <option value="<?php echo esc_attr($action); ?>"><?php echo esc_html($action); ?></option>
                     <?php endif; ?>
                 <?php endforeach; ?>
             </select>
             <br>
             <input type="text" id="new_ajax_action_manual" placeholder="<?php esc_attr_e('Or enter action name manually', 'enterprise-ajax-cache'); ?>" style="width: 300px; max-width: 100%; margin-top: 5px;" />
             <button type="button" class="button button-secondary" id="add_cacheable_action_button"><?php esc_html_e('Add Action', 'enterprise-ajax-cache'); ?></button>
        </div>

        <script type="text/javascript">
            jQuery(document).ready(function($) {
                // Add Action
                $('#add_cacheable_action_button').on('click', function() {
                    var manualAction = $('#new_ajax_action_manual').val().trim();
                    var selectedAction = $('#new_ajax_action_select').val();
                    var actionToAdd = manualAction || selectedAction;
                    actionToAdd = actionToAdd.replace(/[^a-zA-Z0-9_\-]/g, ''); // Basic sanitization similar to sanitize_key

                    if (!actionToAdd) {
                        alert('<?php echo esc_js(__('Please select or enter an action name.', 'enterprise-ajax-cache')); ?>');
                        return;
                    }

                    // Check if already exists in the table
                    if ($('#cacheable-actions-tbody tr[data-action="' + actionToAdd + '"]').length > 0) {
                        alert('<?php echo esc_js(__('This action is already in the list.', 'enterprise-ajax-cache')); ?>');
                        return;
                    }

                    // Add to table
                    var newRowHtml = '<tr data-action="' + actionToAdd + '">' +
                        '<td><input type="hidden" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[cacheable_actions][]" value="' + actionToAdd + '" />' + actionToAdd + '</td>' +
                        '<td><button type="button" class="button button-small remove-cacheable-action" title="<?php esc_attr_e('Remove Action', 'enterprise-ajax-cache'); ?>"><span class="dashicons dashicons-trash"></span></button></td>' +
                        '</tr>';

                    // Remove "no items" row if present
                    $('#cacheable-actions-tbody .no-items').remove();
                    $('#cacheable-actions-tbody').append(newRowHtml);

                    // Reset inputs
                    $('#new_ajax_action_manual').val('');
                    $('#new_ajax_action_select').val('');
                    // Remove added action from select dropdown
                    $('#new_ajax_action_select option[value="' + actionToAdd + '"]').remove();
                     // Trigger change event on tbody for other dependent fields
                    $('#cacheable-actions-tbody').trigger('dynamic-update'); // Use custom event name
                });

                // Remove Action
                $('#cacheable-actions-list').on('click', '.remove-cacheable-action', function() {
                    var row = $(this).closest('tr');
                    var action = row.data('action');
                    row.remove();

                    // Add action back to select dropdown if it was there originally
                    var allActions = <?php echo wp_json_encode($all_ajax_actions); ?>;
                    var existsInOriginalList = allActions && allActions.includes(action);

                    if (existsInOriginalList && $('#new_ajax_action_select option[value="' + action + '"]').length === 0) {
                         $('#new_ajax_action_select').append($('<option>', {
                             value: action,
                             text: action
                         }));
                         // Optional: Sort dropdown options alphabetically after adding back
                        var options = $('#new_ajax_action_select option:not([value=""])'); // Exclude placeholder
                        var arr = options.map(function(_, o) { return { t: $(o).text(), v: o.value }; }).get();
                        arr.sort(function(o1, o2) { // Case-insensitive sort
                             var t1 = o1.t.toLowerCase(); var t2 = o2.t.toLowerCase();
                             return t1 > t2 ? 1 : (t1 < t2 ? -1 : 0);
                        });
                        options.each(function(i, o) {
                          o.value = arr[i].v;
                          $(o).text(arr[i].t);
                        });
                        $('#new_ajax_action_select').val(''); // Reset selection
                    }


                    // Add "no items" row if table becomes empty
                    if ($('#cacheable-actions-tbody tr').length === 0) {
                        $('#cacheable-actions-tbody').append('<tr class="no-items"><td colspan="2"><em><?php esc_html_e('No actions configured yet.', 'enterprise-ajax-cache'); ?></em></td></tr>');
                    }
                     // Trigger change event on tbody for other dependent fields
                     $('#cacheable-actions-tbody').trigger('dynamic-update'); // Use custom event name
                });
            });
        </script>
        <?php
    }

     public function per_action_expiration_callback() {
        $settings = $this->get_settings();
        $per_action_expiration = $settings['per_action_expiration'];
        $cacheable_actions = $settings['cacheable_actions']; // Use current setting value
        $default_expiration = $settings['default_expiration'];
        ?>
        <div id="per-action-expiration-container">
            <p class="description"><?php esc_html_e('Optionally override the default expiration for specific actions. Leave blank to use default.', 'enterprise-ajax-cache'); ?></p>

            <table class="wp-list-table widefat striped" style="width: auto; max-width: 600px;">
                <thead>
                    <tr>
                        <th><?php esc_html_e('Action Name', 'enterprise-ajax-cache'); ?></th>
                        <th><?php esc_html_e('Expiration (seconds)', 'enterprise-ajax-cache'); ?></th>
                    </tr>
                </thead>
                <tbody id="per-action-expiration-tbody">
                    <?php // Content generated by JS based on cacheable actions list ?>
                </tbody>
            </table>
        </div>

        <script type="text/javascript">
            jQuery(document).ready(function($) {
                function updatePerActionExpirationTable() {
                    var tbody = $('#per-action-expiration-tbody');
                    var currentActions = $('#cacheable-actions-tbody tr:not(.no-items)').map(function() {
                        return $(this).data('action');
                    }).get();
                    var existingData = <?php echo wp_json_encode($per_action_expiration); ?> || {};
                    var defaultPlaceholder = '<?php echo esc_js($default_expiration) . ' ' . esc_js(__(' (default)', 'enterprise-ajax-cache')); ?>';

                    tbody.empty(); // Clear existing rows

                    if (currentActions.length === 0) {
                        tbody.html('<tr class="no-items"><td colspan="2"><em><?php esc_html_e('Add actions to the "Cacheable Actions" list first.', 'enterprise-ajax-cache'); ?></em></td></tr>');
                        return;
                    }

                    currentActions.forEach(function(action) {
                        var currentExp = existingData[action] !== undefined ? existingData[action] : '';
                        var inputName = '<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[per_action_expiration][' + action + ']';
                        var newRow = '<tr data-action="' + action + '">' +
                            '<td>' + action + '</td>' +
                            '<td><input type="number" name="' + inputName + '" value="' + currentExp + '" placeholder="' + defaultPlaceholder + '" min="0" step="1" class="small-text" /></td>' +
                            '</tr>';
                        tbody.append(newRow);
                    });
                }

                // Update this table when cacheable actions list changes (using custom event)
                $('#cacheable-actions-tbody').on('dynamic-update', updatePerActionExpirationTable);

                // Initial population on page load
                updatePerActionExpirationTable();
            });
        </script>
        <?php
    }

    // Key Configuration Fields
    public function key_factors_callback() {
        $settings = $this->get_settings();
        $factors = $settings['cache_key_factors'];
        ?>
        <p class="description"><?php esc_html_e('Include these factors in ALL cache keys. Enable if responses vary based on user state.', 'enterprise-ajax-cache'); ?></p>
        <fieldset>
            <legend class="screen-reader-text"><span><?php esc_html_e('Global Cache Key Factors', 'enterprise-ajax-cache'); ?></span></legend>
            <label>
                <input type="checkbox" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[cache_key_factors][user_id]" value="1" <?php checked(1, !empty($factors['user_id'])); ?>/>
                <?php esc_html_e('User ID', 'enterprise-ajax-cache'); ?>
                 <p class="description" style="margin-left: 25px;"><?php esc_html_e('Creates separate caches for logged-in users and guests.', 'enterprise-ajax-cache'); ?></p>
            </label>
            <br/>
            <label>
                <input type="checkbox" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[cache_key_factors][user_roles]" value="1" <?php checked(1, !empty($factors['user_roles'])); ?>/>
                <?php esc_html_e('User Roles', 'enterprise-ajax-cache'); ?>
                 <p class="description" style="margin-left: 25px;"><?php esc_html_e('Creates separate caches based on the user\'s roles (e.g., administrator, subscriber).', 'enterprise-ajax-cache'); ?></p>
            </label>
        </fieldset>
        <?php
    }

    // Shared JS and CSS for Params/Cookies UI
    private function render_key_part_ui_styles() {
        static $styles_rendered = false;
        if ($styles_rendered) return;
        ?>
        <style>
            .key-part-tag-list { list-style: none; margin: 5px 0 0; padding: 0; display: flex; flex-wrap: wrap; gap: 5px; }
            .key-part-tag-list li { margin: 0; padding: 0; }
            .key-part-tag { display: inline-block; background: #f0f0f1; border: 1px solid #c3c4c7; border-radius: 3px; padding: 2px 6px; font-size: 0.9em; word-break: break-all; }
            .remove-key-part { margin-left: 4px; color: #d63638; text-decoration: none; font-weight: bold; cursor: pointer; }
            .key-part-actions { display: flex; gap: 5px; margin-top: 5px; flex-wrap: wrap; }
            .key-part-actions .regular-text { flex-grow: 1; }
        </style>
        <?php
        $styles_rendered = true;
    }

     private function render_key_part_ui_script() {
        static $script_rendered = false;
        if ($script_rendered) return;
        ?>
         <script type="text/javascript">
            jQuery(document).ready(function($) {
                // ---- Key Part UI Logic ----
                function addKeyPart(container, partName, partValue, inputNameFormat) {
                    var list = container.find('.key-part-tag-list');
                    partValue = partValue.trim(); // Trim value
                     if (!partValue) return; // Don't add empty values

                    var inputName = inputNameFormat.replace('%action%', container.closest('tr').data('action')) + '[]'; // Add [] for array

                    // Check if already exists (case-sensitive)
                    if (list.find('input[value="' + partValue + '"]').length > 0) {
                        alert('<?php echo esc_js(__('This item is already in the list.', 'enterprise-ajax-cache')); ?>');
                        return;
                    }

                    list.find('.no-items').remove(); // Remove 'None' message

                    // Escape HTML for display, keep raw value for input
                    var displayValue = $('<div/>').text(partValue).html();

                    var newTag = '<li>' +
                        '<span class="key-part-tag">' + displayValue +
                        '<input type="hidden" name="' + inputName + '" value="' + partValue + '" />' + // Use esc_attr on server-side for name/value
                        '<a href="#" class="remove-key-part" title="<?php echo esc_js(__('Remove', 'enterprise-ajax-cache')); ?>">×</a>' +
                        '</span></li>';
                    list.append(newTag);
                }

                // Add item (Param/Cookie) via Button
                $('.settings_page_enterprise-ajax-cache').on('click', '.add-key-part', function() {
                    var container = $(this).closest('.key-part-container');
                    var inputField = container.find('.new-key-part-input');
                    var partValue = inputField.val();
                    var partName = container.data('part-name');
                    var inputNameFormat = container.data('input-name-format');

                     if (partValue) {
                        addKeyPart(container, partName, partValue, inputNameFormat);
                        inputField.val('');
                    }
                });

                // Add item via Enter key in Text Input
                 $('.settings_page_enterprise-ajax-cache').on('keypress', '.new-key-part-input', function(e) {
                     if (e.which === 13) { // Enter key
                         e.preventDefault();
                         $(this).closest('.key-part-container').find('.add-key-part').click();
                     }
                 });

                 // Add common cookie via Button
                 $('.settings_page_enterprise-ajax-cache').on('click', '.add-common-cookie', function() {
                      var container = $(this).closest('.key-part-container');
                      var selectField = container.find('.common-cookies-select');
                      var partValue = selectField.val();
                      var partName = 'cookie'; // Specific to this button
                      var inputNameFormat = container.data('input-name-format');

                      if (partValue) {
                           addKeyPart(container, partName, partValue, inputNameFormat);
                           selectField.val(''); // Reset dropdown
                      }
                 });


                // Remove item (Param/Cookie)
                $('.settings_page_enterprise-ajax-cache').on('click', '.remove-key-part', function(e) {
                    e.preventDefault();
                    var listItem = $(this).closest('li');
                    var list = listItem.closest('.key-part-tag-list');
                    listItem.remove();

                    if (list.find('li').length === 0) {
                        list.html('<li class="no-items"><em><?php echo esc_js(__('None', 'enterprise-ajax-cache')); ?></em></li>');
                    }
                });

                 // ---- Dynamic Table Update Logic ----

                 // Helper to update Key Part tables (Params, Cookies) based on cacheable actions
                 function updateKeyPartTable(tbodySelector, actions, noActionsMessage, initialData, inputNameFormat, partName, commonOptionsHtml) {
                    var tbody = $(tbodySelector);
                    tbody.empty(); // Clear current rows

                    if (actions.length === 0) {
                        tbody.html('<tr class="no-items"><td colspan="3"><em>' + noActionsMessage + '</em></td></tr>');
                        return;
                    }

                    actions.forEach(function(action) {
                        var actionParts = initialData[action] || [];
                        var tagsHtml = '';
                        if (actionParts.length === 0) {
                            tagsHtml = '<li class="no-items"><em><?php echo esc_js(__('None', 'enterprise-ajax-cache')); ?></em></li>';
                        } else {
                            actionParts.forEach(function(part) {
                                var displayPart = $('<div/>').text(part).html();
                                tagsHtml += '<li><span class="key-part-tag">' + displayPart +
                                            '<input type="hidden" name="' + inputNameFormat.replace('%action%', action) + '[]" value="' + part + '" />' +
                                            '<a href="#" class="remove-key-part" title="<?php echo esc_js(__('Remove', 'enterprise-ajax-cache')); ?>">×</a>' +
                                            '</span></li>';
                            });
                        }

                        var addUiHtml = '<div class="key-part-actions">' +
                            '<input type="text" class="new-key-part-input regular-text" placeholder="' + partName + ' name" />' +
                            '<button type="button" class="button button-secondary add-key-part"><?php echo esc_js(__('Add', 'enterprise-ajax-cache')); ?></button>' +
                            '</div>';

                        if (partName === 'cookie' && commonOptionsHtml) {
                             addUiHtml += '<div style="margin-top: 5px;">' + commonOptionsHtml +
                                          '<button type="button" class="button button-secondary add-common-cookie" style="margin-top: 3px;"><?php echo esc_js(__('Add Selected', 'enterprise-ajax-cache')); ?></button>' +
                                          '</div>';
                        }


                        var newRow = '<tr data-action="' + action + '" class="key-part-container" data-part-name="' + partName + '" data-input-name-format="' + inputNameFormat + '">' +
                            '<td>' + action + '</td>' +
                            '<td><ul class="key-part-tag-list">' + tagsHtml + '</ul></td>' +
                            '<td>' + addUiHtml + '</td>' +
                            '</tr>';
                        tbody.append(newRow);
                    });
                 }

                 // Helper to update Invalidation Rules table
                function updateInvalidationRulesTable(tbodySelector, cacheableActions, watchedPostTypes, postTypeObjects, initialRules) {
                    var tbody = $(tbodySelector);
                    tbody.empty(); // Clear current rows

                    if (watchedPostTypes.length === 0) {
                        tbody.html('<tr class="no-items"><td colspan="2"><em><?php echo esc_js(__('Select "Watched Post Types" first.', 'enterprise-ajax-cache')); ?></em></td></tr>');
                        return;
                    }
                     if (cacheableActions.length === 0) {
                        tbody.html('<tr class="no-items"><td colspan="2"><em><?php echo esc_js(__('Add "Cacheable Actions" first.', 'enterprise-ajax-cache')); ?></em></td></tr>');
                        return;
                    }

                    postTypeObjects.forEach(function(postType) {
                        var postTypeName = postType.name;
                        var postTypeLabel = postType.label;
                        var actionsHtml = '';
                        var rulesForType = initialRules[postTypeName] || [];

                        actionsHtml += '<fieldset>';
                        actionsHtml += '<legend class="screen-reader-text">' + postTypeLabel + ' actions</legend>';
                         cacheableActions.forEach(function(action) {
                            var isChecked = rulesForType.includes(action);
                            actionsHtml += '<label style="display: block; margin-bottom: 3px;">' +
                                '<input type="checkbox" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[invalidation_rules][' + postTypeName + '][]" value="' + action + '" ' + (isChecked ? 'checked="checked"' : '') + '/> ' +
                                action +
                                '</label>';
                        });
                        actionsHtml += '</fieldset>';

                        var newRow = '<tr data-post-type="' + postTypeName + '">' +
                            '<td>' + postTypeLabel + ' (<code>' + postTypeName + '</code>)</td>' +
                            '<td>' + actionsHtml + '</td>' +
                            '</tr>';
                        tbody.append(newRow);
                    });
                }


                // --- Trigger Updates ---
                // Get initial data needed for dynamic updates
                 var initialCacheableActions = $('#cacheable-actions-tbody tr:not(.no-items)').map(function() { return $(this).data('action'); }).get();
                 var initialKeyParams = <?php echo wp_json_encode($this->get_settings()['cache_key_params'] ?? []); ?>;
                 var initialKeyCookies = <?php echo wp_json_encode($this->get_settings()['cache_key_cookies'] ?? []); ?>;
                 var initialInvalidationRules = <?php echo wp_json_encode($this->get_settings()['invalidation_rules'] ?? []); ?>;
                 var watchedPostTypes = <?php echo wp_json_encode($this->get_settings()['watched_post_types'] ?? []); ?>;
                 // Need labels for invalidation table
                 var postTypeObjects = <?php
                    $post_type_data = [];
                    $watched = $this->get_settings()['watched_post_types'] ?? [];
                    foreach ($watched as $pt_name) {
                        $pt_obj = get_post_type_object($pt_name);
                        if ($pt_obj) {
                            $post_type_data[] = ['name' => $pt_obj->name, 'label' => esc_js($pt_obj->label)]; // esc_js for safety in JS context
                        }
                    }
                    echo wp_json_encode($post_type_data);
                  ?>;

                 // Common cookies dropdown HTML (build once)
                 var commonCookiesSelectHtml = '<select class="common-cookies-select regular-text" style="width: 100%;"><option value="">-- <?php echo esc_js(__('Or select common cookie', 'enterprise-ajax-cache')); ?> --</option>';
                 <?php
                    $common_cookies = $this->get_common_cookies_options(); // Assuming you add this helper method
                    foreach($common_cookies as $key => $label) {
                        echo 'commonCookiesSelectHtml += \'<option value="' . esc_js($key) . '">' . esc_js($label) . '</option>\';';
                    }
                 ?>
                 commonCookiesSelectHtml += '</select>';


                 // Listener for when cacheable actions change
                 $('#cacheable-actions-tbody').on('dynamic-update', function() {
                     var currentActions = $('#cacheable-actions-tbody tr:not(.no-items)').map(function() { return $(this).data('action'); }).get();

                     // Update Params Table
                     updateKeyPartTable(
                         '#key-params-tbody', currentActions,
                         '<?php echo esc_js(__('Add cacheable actions first.', 'enterprise-ajax-cache')); ?>',
                         initialKeyParams,
                         '<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[cache_key_params][%action%]',
                         'parameter'
                     );

                      // Update Cookies Table
                     updateKeyPartTable(
                         '#key-cookies-tbody', currentActions,
                         '<?php echo esc_js(__('Add cacheable actions first.', 'enterprise-ajax-cache')); ?>',
                         initialKeyCookies,
                         '<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[cache_key_cookies][%action%]',
                         'cookie',
                         commonCookiesSelectHtml // Pass common cookie dropdown
                     );

                    // Update Invalidation Rules Table
                    updateInvalidationRulesTable(
                        '#invalidation-rules-tbody', currentActions,
                        watchedPostTypes, postTypeObjects, initialInvalidationRules
                    );
                 });

                 // Trigger initial update on page load
                 $('#cacheable-actions-tbody').trigger('dynamic-update');

            });
        </script>
        <?php
        $script_rendered = true;
    }


    public function key_params_callback() {
        $settings = $this->get_settings();
        $cacheable_actions = $settings['cacheable_actions']; // Needed for initial state check

        $this->render_key_part_ui_styles();
        ?>
        <p class="description"><?php esc_html_e('Include specific request parameters (e.g., from $_GET or $_POST) in the cache key for certain actions.', 'enterprise-ajax-cache'); ?></p>

        <table class="wp-list-table widefat striped" style="width: auto; max-width: 800px;">
            <thead>
                <tr>
                    <th style="width:30%"><?php esc_html_e('Action Name', 'enterprise-ajax-cache'); ?></th>
                    <th style="width:40%"><?php esc_html_e('Included Parameters', 'enterprise-ajax-cache'); ?></th>
                    <th style="width:30%"><?php esc_html_e('Add Parameter', 'enterprise-ajax-cache'); ?></th>
                </tr>
            </thead>
            <tbody id="key-params-tbody">
                <?php // Content generated by JS ?>
                 <?php if (empty($cacheable_actions)) : ?>
                    <tr class="no-items"><td colspan="3"><em><?php esc_html_e('Add cacheable actions first.', 'enterprise-ajax-cache'); ?></em></td></tr>
                 <?php endif; ?>
            </tbody>
        </table>
        <?php
        $this->render_key_part_ui_script(); // Ensure script runs
    }

    // Helper for common cookies
    private function get_common_cookies_options() {
         $common_cookies = array(
            'wordpress_logged_in_' . COOKIEHASH => __('WordPress Login', 'enterprise-ajax-cache'),
            'wp_woocommerce_session_' . COOKIEHASH => __('WooCommerce Session', 'enterprise-ajax-cache'),
            'woocommerce_cart_hash' => __('WooCommerce Cart Hash', 'enterprise-ajax-cache'),
            'woocommerce_items_in_cart' => __('WooCommerce Items in Cart', 'enterprise-ajax-cache'),
            'comment_author_' . COOKIEHASH => __('Comment Author', 'enterprise-ajax-cache'),
            'comment_author_email_' . COOKIEHASH => __('Comment Author Email', 'enterprise-ajax-cache'),
         );
         ksort($common_cookies);
         return apply_filters('ajax_cache_common_cookies_options', $common_cookies);
    }

     public function key_cookies_callback() {
        $settings = $this->get_settings();
        $cacheable_actions = $settings['cacheable_actions']; // Needed for initial state check

        $this->render_key_part_ui_styles();
        ?>
         <p class="description"><?php esc_html_e('Include specific cookies in the cache key for certain actions (e.g., session or preference cookies).', 'enterprise-ajax-cache'); ?></p>

        <table class="wp-list-table widefat striped" style="width: auto; max-width: 800px;">
            <thead>
                <tr>
                    <th style="width:30%"><?php esc_html_e('Action Name', 'enterprise-ajax-cache'); ?></th>
                    <th style="width:40%"><?php esc_html_e('Included Cookies', 'enterprise-ajax-cache'); ?></th>
                    <th style="width:30%"><?php esc_html_e('Add Cookie', 'enterprise-ajax-cache'); ?></th>
                </tr>
            </thead>
            <tbody id="key-cookies-tbody">
                 <?php // Content generated by JS ?>
                 <?php if (empty($cacheable_actions)) : ?>
                    <tr class="no-items"><td colspan="3"><em><?php esc_html_e('Add cacheable actions first.', 'enterprise-ajax-cache'); ?></em></td></tr>
                 <?php endif; ?>
            </tbody>
        </table>
        <?php
        $this->render_key_part_ui_script(); // Ensure script runs
    }

    // Invalidation Fields
    public function watched_post_types_callback() {
        $settings = $this->get_settings();
        $watched_types = $settings['watched_post_types'];
        // Get post types that have a UI and are public or private (but not built-in like revision, nav_menu_item)
        $all_post_types = get_post_types(['show_ui' => true], 'objects');
        $excluded_types = ['attachment', 'revision', 'nav_menu_item', 'custom_css', 'customize_changeset', 'oembed_cache', 'user_request', 'wp_block'];
        ?>
        <p class="description"><?php esc_html_e('Select post types that should trigger cache invalidation rules when saved.', 'enterprise-ajax-cache'); ?></p>
         <fieldset>
             <legend class="screen-reader-text"><span><?php esc_html_e('Watched Post Types', 'enterprise-ajax-cache'); ?></span></legend>
             <?php if (empty($all_post_types)): ?>
                <p><?php esc_html_e('No relevant post types found.', 'enterprise-ajax-cache'); ?></p>
             <?php else: ?>
                <?php foreach ($all_post_types as $post_type) : ?>
                    <?php if (in_array($post_type->name, $excluded_types)) continue; ?>
                    <label style="display: block; margin-bottom: 5px;">
                        <input type="checkbox" name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[watched_post_types][]" value="<?php echo esc_attr($post_type->name); ?>" <?php checked(in_array($post_type->name, $watched_types)); ?> />
                        <?php echo esc_html($post_type->label); ?> (<code><?php echo esc_html($post_type->name); ?></code>)
                    </label>
                <?php endforeach; ?>
            <?php endif; ?>
        </fieldset>
        <?php
    }

    public function invalidation_rules_callback() {
        $settings = $this->get_settings();
        $watched_types = $settings['watched_post_types'];
        $cacheable_actions = $settings['cacheable_actions'];
        ?>
         <p class="description"><?php esc_html_e('Define which cached AJAX actions should be cleared when a post of a specific watched type is saved.', 'enterprise-ajax-cache'); ?></p>

         <table class="wp-list-table widefat striped" style="width: auto; max-width: 800px;">
            <thead>
                <tr>
                    <th style="width:30%"><?php esc_html_e('Post Type', 'enterprise-ajax-cache'); ?></th>
                    <th style="width:70%"><?php esc_html_e('Actions to Invalidate', 'enterprise-ajax-cache'); ?></th>
                </tr>
            </thead>
             <tbody id="invalidation-rules-tbody">
                  <?php // Content generated by JS ?>
                  <?php if (empty($watched_types)) : ?>
                     <tr class="no-items"><td colspan="2"><em><?php esc_html_e('Select "Watched Post Types" first.', 'enterprise-ajax-cache'); ?></em></td></tr>
                 <?php elseif (empty($cacheable_actions)): ?>
                     <tr class="no-items"><td colspan="2"><em><?php esc_html_e('Add "Cacheable Actions" first.', 'enterprise-ajax-cache'); ?></em></td></tr>
                 <?php endif; ?>
             </tbody>
         </table>
        <?php
        $this->render_key_part_ui_script(); // Ensure script runs (it contains the listener)
    }

    // Schedule Helpers
    private function get_schedule_options() {
         // Get WP schedules and add 'never' and 'weekly' if missing
        $schedules = wp_get_schedules();
        $options = ['never' => __('Never', 'enterprise-ajax-cache')];
        if (!isset($schedules['weekly'])) {
            // Add weekly if core doesn't define it (it usually doesn't by default)
             $schedules['weekly'] = [
                 'interval' => WEEK_IN_SECONDS,
                 'display' => __('Weekly', 'enterprise-ajax-cache')
             ];
        }
        // Ensure standard schedules are present even if filtered out
        $standard = ['hourly', 'twicedaily', 'daily'];
        foreach($standard as $std) {
             if (!isset($schedules[$std])) {
                 $interval = 0;
                 if ($std === 'hourly') $interval = HOUR_IN_SECONDS;
                 if ($std === 'twicedaily') $interval = 12 * HOUR_IN_SECONDS;
                 if ($std === 'daily') $interval = DAY_IN_SECONDS;
                 if ($interval > 0) {
                      $schedules[$std] = ['interval' => $interval, 'display' => ucfirst($std)];
                 }
             }
        }

        foreach ($schedules as $key => $details) {
            $options[$key] = $details['display'];
        }
        return $options;
    }

    public function auto_purge_schedule_callback() {
        $settings = $this->get_settings();
        $schedule = $settings['auto_purge_schedule'];
        $schedules = $this->get_schedule_options();
        ?>
        <select name="<?php echo esc_attr(AJAX_CACHE_SETTINGS_KEY); ?>[auto_purge_schedule]">
            <?php foreach ($schedules as $key => $label) : ?>
                <option value="<?php echo esc_attr($key); ?>" <?php selected($key, $schedule); ?>>
                    <?php echo esc_html($label); ?>
                </option>
            <?php endforeach; ?>
        </select>
        <p class="description"><?php esc_html_e('Automatically purge all AJAX caches based on this schedule.', 'enterprise-ajax-cache'); ?></p>
        <?php
        // Display next scheduled time if applicable
        $next_run = wp_next_scheduled('ajax_cache_auto_purge');
        if ($next_run) {
            echo '<p><small>' . sprintf(
                esc_html__('Next run scheduled for: %s (%s from now)', 'enterprise-ajax-cache'),
                esc_html(get_date_from_gmt(date('Y-m-d H:i:s', $next_run), 'Y-m-d H:i:s')),
                esc_html(human_time_diff($next_run, time()))
            ) . '</small></p>';
        } elseif ($schedule !== 'never') {
            echo '<p><small style="color: #d63638;">' . esc_html__('Warning: Schedule set but no event found. Saving settings should reschedule.', 'enterprise-ajax-cache') . '</small></p>';
        }
        ?>
        <?php
    }


    /**
     * Utility function to get potentially registered AJAX actions.
     * Scans $wp_filter and adds known common actions.
     *
     * @return array List of discovered AJAX action names, sorted.
     */
    public function get_registered_ajax_actions() {
        global $wp_filter;
        $ajax_actions = array();

        // Scan $wp_filter for 'wp_ajax_' and 'wp_ajax_nopriv_' hooks
        if (isset($wp_filter) && is_array($wp_filter)) {
            $prefix_public = 'wp_ajax_';
            $prefix_nopriv = 'wp_ajax_nopriv_';
            $len_public = strlen($prefix_public);
            $len_nopriv = strlen($prefix_nopriv);

            foreach (array_keys($wp_filter) as $filter_name) {
                if (strpos($filter_name, $prefix_public) === 0) {
                    $action = substr($filter_name, $len_public);
                    if (!empty($action) && $action !== 'heartbeat') { // Exclude heartbeat by default
                        $ajax_actions[] = $action;
                    }
                } elseif (strpos($filter_name, $prefix_nopriv) === 0) {
                    $action = substr($filter_name, $len_nopriv);
                    if (!empty($action)) {
                         $ajax_actions[] = $action;
                    }
                }
            }
        }

        // Add commonly used AJAX actions from popular plugins/themes (users can add more manually)
        $common_actions = [
            // WooCommerce
            'woocommerce_get_refreshed_fragments', 'woocommerce_add_to_cart', 'woocommerce_update_cart',
            'woocommerce_apply_coupon', 'woocommerce_remove_coupon', 'woocommerce_update_shipping_method',
            'woocommerce_update_order_review', 'woocommerce_checkout', 'add_to_cart', 'wc_fragments_refresh',
            'get_variation', 'woocommerce_load_variations',
            // Gravity Forms (might have dynamic parts)
            'gf_get_field_inputs', 'gf_select_screen_options', 'rg_update_lead_property',
            // Contact Form 7
            'wpcf7_submit',
            // Elementor
            'elementor_ajax', 'elementor_pro_forms_send_form',
            // WP Core Admin
            'query-attachments', 'get-comments', 'wp-link-ajax', 'menu-quick-search', 'get-community-events',
            'dashboard-widgets', 'meta-box-order', 'closed-postboxes', 'hidden-columns',
            // WP Core Frontend / Other
            'send-password-reset', 'logged-in',
            // Others (examples)
            'load_more_posts', 'autocomplete_search', 'save_user_preference',
        ];

        $ajax_actions = array_merge($ajax_actions, $common_actions);
        $ajax_actions = array_map('trim', $ajax_actions); // Trim whitespace
        $ajax_actions = array_filter($ajax_actions); // Remove empty
        $ajax_actions = array_unique($ajax_actions);
        sort($ajax_actions);

        return apply_filters('ajax_cache_discovered_actions_list', $ajax_actions);
    }

    /**
     * Export settings handler (connected via admin_post_* action).
     */
    public function export_settings() {
        // Security checks
        if (!current_user_can('manage_options') || !isset($_POST['ajax_cache_export_nonce']) || !wp_verify_nonce($_POST['ajax_cache_export_nonce'], 'ajax_cache_export_settings')) {
            wp_die(__('Security check failed.', 'enterprise-ajax-cache'));
        }

        $settings = get_option(AJAX_CACHE_SETTINGS_KEY, $this->defaults);
        $filename = 'ajax-cache-settings-' . date('Y-m-d') . '.json';
        $settings_json = wp_json_encode($settings, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        // Force download headers
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename=' . $filename);
        header('Pragma: no-cache');
        header('Expires: 0');

        echo $settings_json;
        exit;
    }

    /**
     * Import settings handler (connected via admin_post_* action).
     */
    public function import_settings() {
        // Security checks
        if (!current_user_can('manage_options') || !isset($_POST['ajax_cache_import_nonce']) || !wp_verify_nonce($_POST['ajax_cache_import_nonce'], 'ajax_cache_import_settings')) {
            wp_die(__('Security check failed.', 'enterprise-ajax-cache'));
        }

        $redirect_url = admin_url('tools.php?page=enterprise-ajax-cache&tab=tools');

        // Check file upload
        if (!isset($_FILES['settings_file']) || empty($_FILES['settings_file']['tmp_name']) || $_FILES['settings_file']['error'] !== UPLOAD_ERR_OK) {
            $error_code = isset($_FILES['settings_file']['error']) ? $_FILES['settings_file']['error'] : 'unknown';
            wp_redirect(add_query_arg('import_error', $error_code, $redirect_url));
            exit;
        }

        // Check file type (basic JSON check)
        if (strtolower(pathinfo($_FILES['settings_file']['name'], PATHINFO_EXTENSION)) !== 'json') {
             wp_redirect(add_query_arg('import_error', 'invalid_type', $redirect_url));
             exit;
        }

        // Check file size (e.g., max 1MB)
        if ($_FILES['settings_file']['size'] > 1024 * 1024) {
            wp_redirect(add_query_arg('import_error', 'size_limit', $redirect_url));
            exit;
        }


        $file_content = file_get_contents($_FILES['settings_file']['tmp_name']);
        if ($file_content === false) {
            wp_redirect(add_query_arg('import_error', 'read_failed', $redirect_url));
            exit;
        }

        // Decode JSON
        $settings = json_decode($file_content, true);
        if ($settings === null && json_last_error() !== JSON_ERROR_NONE) {
            wp_redirect(add_query_arg('import_error', 'invalid_json_' . json_last_error(), $redirect_url));
            exit;
        }

        // Sanitize and save settings (use the existing sanitize method)
        // This also triggers reload and cron update inside sanitize_settings.
        $sanitized_settings = $this->sanitize_settings($settings);
        $update_result = update_option(AJAX_CACHE_SETTINGS_KEY, $sanitized_settings);

        wp_redirect(add_query_arg('import_success', '1', $redirect_url));
        exit;
    }

    /**
     * Reset statistics handler (triggered by link click).
     */
    public function reset_statistics() {
        // Check if the action is triggered
        if (isset($_GET['page']) && $_GET['page'] === 'enterprise-ajax-cache' && isset($_GET['action']) && $_GET['action'] === 'reset_stats') {
            // Verify nonce and capability
            if (!isset($_GET['_wpnonce']) || !wp_verify_nonce($_GET['_wpnonce'], 'reset_ajax_cache_stats') || !current_user_can('manage_options')) {
                 wp_die(__('Security check failed.', 'enterprise-ajax-cache'));
            }

            // Reset stats option
            update_option(AJAX_CACHE_STATS_OPTION, self::get_default_stats());

             $this->plugin->get_logger()->info("Cache statistics reset by user.");

            // Redirect back to statistics tab with success message
            wp_redirect(add_query_arg(array('page' => 'enterprise-ajax-cache', 'tab' => 'statistics', 'message' => 'stats-reset'), admin_url('tools.php')));
            exit;
        }
    }

    /**
     * Display admin notices for import/export results or other messages.
     */
    public function admin_notices() {
        // Only show on our settings page or related actions
        $screen = get_current_screen();
        // Check if screen is null or not the settings page
        if (!$screen || !in_array($screen->id, ['tools_page_enterprise-ajax-cache', 'admin_page_enterprise-ajax-cache'])) { // Check both possible slugs
           // Allow activation errors globally
           if (!isset($_GET['activate']) && !isset($_GET['plugin_status'])) { // Check conditions where activation notices might appear
                // return; // Uncomment to restrict notices strictly to the settings page
           }
        }

         // Settings saved notice (WP default)
         // settings_errors('ajax_cache_settings_group'); // Handled via query args below

        // Custom messages via query args
        if (isset($_GET['page']) && $_GET['page'] === 'enterprise-ajax-cache') {
             if (isset($_GET['message'])) {
                 $message_code = sanitize_key($_GET['message']);
                 $message_text = '';
                 $message_type = 'success'; // Default type

                 switch ($message_code) {
                     case 'settings-imported': // Kept for compatibility if used elsewhere
                     case 'import_success':    // Use consistent code
                         $message_text = __('Settings imported successfully.', 'enterprise-ajax-cache');
                         break;
                     case 'import-error': // Kept for compatibility
                         $message_text = __('Settings import failed.', 'enterprise-ajax-cache');
                         if (isset($_GET['error_detail'])) {
                              $message_text .= ' ' . esc_html(sanitize_text_field(urldecode($_GET['error_detail'])));
                         }
                         $message_type = 'error';
                         break;
                     case 'stats-reset':
                         $message_text = __('Cache statistics have been reset.', 'enterprise-ajax-cache');
                         break;
                     case 'cache-cleared-all':
                         $count = isset($_GET['count']) ? absint($_GET['count']) : 0;
                         $message_text = sprintf(_n('All AJAX caches cleared (approx. %d entry removed).', 'All AJAX caches cleared (approx. %d entries removed).', $count, 'enterprise-ajax-cache'), $count);
                         break;
                     case 'cache-cleared-specific':
                         $count = isset($_GET['count']) ? absint($_GET['count']) : 0;
                         $action = isset($_GET['action_cleared']) ? sanitize_key($_GET['action_cleared']) : 'unknown';
                         $message_text = sprintf(_n('Cache purge triggered for action "%s" (approx. %d entry removed).', 'Cache purge triggered for action "%s" (approx. %d entries removed).', $count, 'enterprise-ajax-cache'), esc_html($action), $count);
                          // If count is 0, maybe adjust message?
                          if ($count === 0 && $action !== 'unknown') {
                              $message_text = sprintf(__('Cache purge triggered for action "%s" (or no matching entries found).', 'enterprise-ajax-cache'), esc_html($action));
                          }
                         break;
                     case 'logs-cleared':
                         $message_text = __('Database logs cleared successfully.', 'enterprise-ajax-cache');
                         break;
                     case 'log-file-cleared':
                          $message_text = __('Log file cleared successfully.', 'enterprise-ajax-cache');
                         break;
                     case 'log-file-clear-failed':
                         $message_text = __('Failed to clear log file. Check file permissions.', 'enterprise-ajax-cache');
                         $message_type = 'error';
                         break;
                 }

                 if (!empty($message_text)) {
                     echo '<div class="notice notice-' . esc_attr($message_type) . ' is-dismissible"><p>' . wp_kses_post($message_text) . '</p></div>';
                 }
            }

             // Import errors from import handler redirection
             if (isset($_GET['import_error'])) {
                 $error_code = sanitize_key($_GET['import_error']);
                 $error_message = __('Settings import failed.', 'enterprise-ajax-cache');
                 switch($error_code) {
                     case 'invalid_type': $error_message .= ' ' . __('Invalid file type. Please upload a .json file.', 'enterprise-ajax-cache'); break;
                     case 'size_limit': $error_message .= ' ' . __('File size exceeds limit.', 'enterprise-ajax-cache'); break;
                     case 'read_failed': $error_message .= ' ' . __('Could not read the uploaded file.', 'enterprise-ajax-cache'); break;
                     case 'invalid_json': $error_message .= ' ' . __('Invalid JSON format in the file.', 'enterprise-ajax-cache'); break;
                     default: // Includes upload errors like UPLOAD_ERR_INI_SIZE etc.
                        if (strpos($error_code, 'invalid_json_') === 0) {
                            $json_error = substr($error_code, strlen('invalid_json_'));
                            $json_error_msg = json_last_error_msg(); // Get human-readable error
                            $error_message .= ' ' . sprintf(__('JSON decode error: %s', 'enterprise-ajax-cache'), $json_error_msg) . ' (' . esc_html($json_error) . ')';
                        } else {
                            // Try to map upload error codes to messages
                            $upload_errors = [
                                UPLOAD_ERR_INI_SIZE => __('File exceeds upload_max_filesize directive in php.ini.', 'enterprise-ajax-cache'),
                                UPLOAD_ERR_FORM_SIZE => __('File exceeds MAX_FILE_SIZE directive specified in the HTML form.', 'enterprise-ajax-cache'),
                                UPLOAD_ERR_PARTIAL => __('File was only partially uploaded.', 'enterprise-ajax-cache'),
                                UPLOAD_ERR_NO_FILE => __('No file was uploaded.', 'enterprise-ajax-cache'),
                                UPLOAD_ERR_NO_TMP_DIR => __('Missing temporary folder.', 'enterprise-ajax-cache'),
                                UPLOAD_ERR_CANT_WRITE => __('Failed to write file to disk.', 'enterprise-ajax-cache'),
                                UPLOAD_ERR_EXTENSION => __('A PHP extension stopped the file upload.', 'enterprise-ajax-cache'),
                            ];
                            $upload_error_int = intval($error_code); // Convert code to int if possible
                            $upload_message = $upload_errors[$upload_error_int] ?? sprintf(__('Upload error code: %s', 'enterprise-ajax-cache'), esc_html($error_code));
                            $error_message .= ' ' . $upload_message;
                        }
                        break;

                 }
                 echo '<div class="notice notice-error is-dismissible"><p>' . esc_html($error_message) . '</p></div>';
             }
        }
    }


    /**
     * Render the main settings page HTML structure with tabs.
     */
    public function render_settings_page() {
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'enterprise-ajax-cache'));
        }

        // Handle direct form submissions for cache clearing (POST request) - Placed early before headers might be sent by notices
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (isset($_POST['action']) && $_POST['action'] === 'clear_all_caches' && isset($_POST['ajax_cache_clear_all_nonce'])) {
                if (wp_verify_nonce($_POST['ajax_cache_clear_all_nonce'], 'ajax_cache_clear_all')) {
                    $count = $this->plugin->purge_all_caches();
                     $this->plugin->get_logger()->info("All caches cleared manually by user.", ['count' => $count]);
                    wp_redirect(add_query_arg(array('page' => 'enterprise-ajax-cache', 'tab' => 'tools', 'message' => 'cache-cleared-all', 'count' => $count), admin_url('tools.php')));
                    exit;
                } else {
                    wp_die(__('Security check failed.', 'enterprise-ajax-cache'));
                }
            }
            if (isset($_POST['action']) && $_POST['action'] === 'clear_specific_cache' && isset($_POST['ajax_cache_clear_specific_nonce'])) {
                 if (wp_verify_nonce($_POST['ajax_cache_clear_specific_nonce'], 'ajax_cache_clear_specific')) {
                    $action_to_clear = isset($_POST['cache_action']) ? sanitize_key($_POST['cache_action']) : '';
                    $count = 0;
                    if (!empty($action_to_clear)) {
                        // Note: purge_cache_by_action currently purges all, so count is total.
                        $count = $this->plugin->purge_cache_by_action($action_to_clear);
                         $this->plugin->get_logger()->info("Specific cache cleared manually by user.", ['action' => $action_to_clear, 'count' => $count]);
                    }
                     wp_redirect(add_query_arg(array('page' => 'enterprise-ajax-cache', 'tab' => 'tools', 'message' => 'cache-cleared-specific', 'count' => $count, 'action_cleared' => $action_to_clear), admin_url('tools.php')));
                     exit;
                } else {
                    wp_die(__('Security check failed.', 'enterprise-ajax-cache'));
                }
            }
        }


        // Get current tab
        $current_tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'general';

        // Define tabs
        $tabs = array(
            'general' => __('General', 'enterprise-ajax-cache'),
            'logging' => __('Logging', 'enterprise-ajax-cache'),
            'storage' => __('Storage', 'enterprise-ajax-cache'),
            'actions' => __('Actions & Expiration', 'enterprise-ajax-cache'),
            'keys' => __('Cache Keys', 'enterprise-ajax-cache'),
            'invalidation' => __('Invalidation', 'enterprise-ajax-cache'),
            'statistics' => __('Statistics', 'enterprise-ajax-cache'),
            'logs' => __('Log Viewer', 'enterprise-ajax-cache'),
            'tools' => __('Tools', 'enterprise-ajax-cache'),
        );

        ?>
        <div class="wrap ajax-cache-settings-wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

            <?php settings_errors('ajax_cache_settings_group'); // Show default WP settings errors ?>

            <nav class="nav-tab-wrapper wp-clearfix" aria-label="<?php esc_attr_e('Secondary menu', 'enterprise-ajax-cache'); ?>">
                <?php foreach ($tabs as $tab_slug => $tab_name) : ?>
                    <a href="<?php echo esc_url(admin_url('tools.php?page=enterprise-ajax-cache&tab=' . $tab_slug)); ?>"
                       class="nav-tab <?php echo $current_tab === $tab_slug ? 'nav-tab-active' : ''; ?>"
                       aria-current="<?php echo $current_tab === $tab_slug ? 'page' : 'false'; ?>">
                        <?php echo esc_html($tab_name); ?>
                    </a>
                <?php endforeach; ?>
            </nav>

            <div class="tab-content" style="margin-top: 20px;">
                <?php
                // Display content based on the active tab
                switch ($current_tab) {
                    case 'logging':
                        $this->render_logging_tab();
                        break;
                    case 'storage':
                         $this->render_storage_tab();
                        break;
                    case 'actions':
                         $this->render_actions_tab();
                        break;
                    case 'keys':
                         $this->render_keys_tab();
                        break;
                    case 'invalidation':
                         $this->render_invalidation_tab();
                        break;
                    case 'statistics':
                        $this->render_statistics_tab();
                        break;
                    case 'logs':
                        $this->render_logs_tab();
                        break;
                    case 'tools':
                        $this->render_tools_tab();
                        break;
                    case 'general':
                    default:
                        $this->render_general_tab();
                        break;
                }
                ?>
            </div><!-- /.tab-content -->

        </div><!-- /.wrap -->
        <style>
            /* Add some basic styling */
            .ajax-cache-settings-wrap .form-table th { width: 200px; }
            .ajax-cache-settings-wrap .card { background: #fff; border: 1px solid #c3c4c7; box-shadow: 0 1px 1px rgba(0,0,0,.04); padding: 20px; margin-top: 20px; max-width: 960px; }
            .ajax-cache-settings-wrap .card h2, .ajax-cache-settings-wrap .card h3 { margin-top: 0; padding-bottom: 10px; border-bottom: 1px solid #eee; }
            .ajax-cache-settings-wrap .notice { margin-bottom: 15px; margin-top: 15px; } /* Ensure notices have margin */
            .ajax-cache-settings-wrap .wp-list-table { margin-bottom: 15px; }
        </style>
        <?php
    }

    /** Render specific tab content */
    private function render_general_tab() {
        ?>
        <form method="post" action="options.php">
            <?php
            settings_fields('ajax_cache_settings_group'); // Use the group name
            ?>
            <h2 class="title"><?php esc_html_e('General Settings', 'enterprise-ajax-cache'); ?></h2>
            <?php $this->general_section_callback(); ?>
            <table class="form-table" role="presentation">
                <?php do_settings_fields('enterprise_ajax_cache_page', 'ajax_cache_general_section'); ?>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }
     private function render_logging_tab() {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('ajax_cache_settings_group'); ?>
            <h2 class="title"><?php esc_html_e('Logging Settings', 'enterprise-ajax-cache'); ?></h2>
            <?php $this->logging_section_callback(); ?>
            <table class="form-table" role="presentation">
                <?php do_settings_fields('enterprise_ajax_cache_page', 'ajax_cache_logging_section'); ?>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }
     private function render_storage_tab() {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('ajax_cache_settings_group'); ?>
            <h2 class="title"><?php esc_html_e('Cache Storage Settings', 'enterprise-ajax-cache'); ?></h2>
             <?php $this->storage_section_callback(); ?>
            <table class="form-table" role="presentation">
                <?php do_settings_fields('enterprise_ajax_cache_page', 'ajax_cache_storage_section'); ?>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }
     private function render_actions_tab() {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('ajax_cache_settings_group'); ?>
            <h2 class="title"><?php esc_html_e('Cacheable Actions & Expiration', 'enterprise-ajax-cache'); ?></h2>
             <?php $this->actions_section_callback(); ?>
            <table class="form-table" role="presentation">
                <?php do_settings_fields('enterprise_ajax_cache_page', 'ajax_cache_actions_section'); ?>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }
     private function render_keys_tab() {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('ajax_cache_settings_group'); ?>
            <h2 class="title"><?php esc_html_e('Cache Key Configuration', 'enterprise-ajax-cache'); ?></h2>
             <?php $this->key_section_callback(); ?>
            <table class="form-table" role="presentation">
                <?php do_settings_fields('enterprise_ajax_cache_page', 'ajax_cache_key_section'); ?>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }
     private function render_invalidation_tab() {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields('ajax_cache_settings_group'); ?>
             <h2 class="title"><?php esc_html_e('Cache Invalidation Settings', 'enterprise-ajax-cache'); ?></h2>
             <?php $this->invalidation_section_callback(); ?>
            <table class="form-table" role="presentation">
                <?php do_settings_fields('enterprise_ajax_cache_page', 'ajax_cache_invalidation_section'); ?>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }
    private function render_statistics_tab() {
        $stats = get_option(AJAX_CACHE_STATS_OPTION, self::get_default_stats());
        $total_requests = $stats['hits'] + $stats['misses'];
        $hit_ratio = ($total_requests > 0) ? round(($stats['hits'] / $total_requests) * 100, 2) : 0;
        ?>
        <div class="card">
            <h3><?php esc_html_e('Cache Performance Metrics', 'enterprise-ajax-cache'); ?></h3>
            <table class="widefat striped" style="width: auto; max-width: 400px;">
                <tbody>
                <tr><th><?php esc_html_e('Cache Hits', 'enterprise-ajax-cache'); ?></th><td><?php echo esc_html(number_format_i18n($stats['hits'])); ?></td></tr>
                <tr><th><?php esc_html_e('Cache Misses', 'enterprise-ajax-cache'); ?></th><td><?php echo esc_html(number_format_i18n($stats['misses'])); ?></td></tr>
                <tr><th><?php esc_html_e('Total Handled Requests', 'enterprise-ajax-cache'); ?></th><td><?php echo esc_html(number_format_i18n($total_requests)); ?></td></tr>
                <tr><th><?php esc_html_e('Cache Hit Ratio', 'enterprise-ajax-cache'); ?></th><td><?php echo esc_html($hit_ratio); ?>%</td></tr>
                <tr><th><?php esc_html_e('Cache Sets (Writes)', 'enterprise-ajax-cache'); ?></th><td><?php echo esc_html(number_format_i18n($stats['sets'])); ?></td></tr>
                <tr><th><?php esc_html_e('Cache Purges (Events)', 'enterprise-ajax-cache'); ?></th><td><?php echo esc_html(number_format_i18n($stats['purges'])); ?></td></tr>
                <?php if ($stats['last_purge'] > 0) : ?>
                    <tr>
                        <th><?php esc_html_e('Last Purge Time', 'enterprise-ajax-cache'); ?></th>
                        <td>
                            <?php
                            // Ensure timestamp is treated correctly based on WP timezone settings
                            echo esc_html(wp_date(get_option('date_format') . ' ' . get_option('time_format'), $stats['last_purge']));
                            echo ' (' . sprintf(esc_html__('%s ago', 'enterprise-ajax-cache'), esc_html(human_time_diff($stats['last_purge'], time()))) . ')';
                            ?>
                        </td>
                    </tr>
                <?php else: ?>
                     <tr><th><?php esc_html_e('Last Purge Time', 'enterprise-ajax-cache'); ?></th><td><?php esc_html_e('Never', 'enterprise-ajax-cache'); ?></td></tr>
                <?php endif; ?>
                </tbody>
            </table>
            <p>
                <?php
                // Link to reset stats with nonce
                $reset_url = add_query_arg(array(
                    'page' => 'enterprise-ajax-cache',
                    'action' => 'reset_stats',
                    '_wpnonce' => wp_create_nonce('reset_ajax_cache_stats')
                ), admin_url('tools.php'));
                ?>
                <a href="<?php echo esc_url($reset_url); ?>" class="button button-secondary" onclick="return confirm('<?php echo esc_js(__('Are you sure you want to reset all cache statistics?', 'enterprise-ajax-cache')); ?>');">
                    <?php esc_html_e('Reset Statistics', 'enterprise-ajax-cache'); ?>
                </a>
            </p>
        </div>

         <div class="card">
            <h3><?php esc_html_e('Cache Backend Status', 'enterprise-ajax-cache'); ?></h3>
            <?php
            $settings = $this->get_settings();
            $backend = $settings['cache_backend'];
            $backend_options = $this->get_backend_options();
            $backend_label = isset($backend_options[$backend]) ? $backend_options[$backend] : __('Unknown', 'enterprise-ajax-cache');

            echo '<p><strong>' . esc_html__('Active Cache Backend:', 'enterprise-ajax-cache') . '</strong> ' . esc_html($backend_label) . '</p>';

            switch ($backend) {
                case 'redis':
                    if (function_exists('wp_redis_get_info')) {
                         $info = wp_redis_get_info();
                         if (($info['status'] ?? 'Unknown') === 'Connected') {
                             echo '<p style="color:green;">' . esc_html__('Redis seems connected and status reported.', 'enterprise-ajax-cache') . '</p>';
                             // Avoid printing sensitive info like password from $info['client'] options
                             unset($info['client']); // Remove client object before printing
                             echo '<pre style="font-size: smaller; background: #f9f9f9; padding: 5px; max-height: 150px; overflow: auto;">' . esc_html(print_r($info, true)) . '</pre>';
                         } else {
                             echo '<p style="color:red;">' . esc_html__('Redis connection status reported as:', 'enterprise-ajax-cache') . ' ' . esc_html($info['status'] ?? 'Unknown') . '</p>';
                         }
                    } else {
                         echo '<p style="color:orange;">' . esc_html__('Cannot verify Redis status (requires a compatible Redis Object Cache plugin).', 'enterprise-ajax-cache') . '</p>';
                    }
                    break;

                case 'memcached':
                    if (wp_using_ext_object_cache()) {
                        $is_memcached = false; $cache_class = 'N/A';
                         if (isset($GLOBALS['wp_object_cache']) && is_object($GLOBALS['wp_object_cache'])) {
                             $cache_class = get_class($GLOBALS['wp_object_cache']);
                             if (stripos($cache_class, 'Memcached') !== false) $is_memcached = true;
                              if (property_exists($GLOBALS['wp_object_cache'], 'is_memcached')) $is_memcached = $GLOBALS['wp_object_cache']->is_memcached;
                               if (method_exists($GLOBALS['wp_object_cache'], 'get_mc')) $is_memcached = true;

                             if ($is_memcached) {
                                echo '<p style="color:green;">' . sprintf(esc_html__('Memcached Object Cache detected (Class: %s).', 'enterprise-ajax-cache'), esc_html($cache_class)) . '</p>';
                                if (method_exists($GLOBALS['wp_object_cache'], 'getStats')) {
                                     // Avoid outputting potentially huge stats array directly
                                     echo '<p><small>' . esc_html__('Memcached stats seem available via object cache.', 'enterprise-ajax-cache') . '</small></p>';
                                }
                             } else {
                                echo '<p style="color:orange;">' . sprintf(esc_html__('External Object Cache detected (Class: %s), but may not be Memcached.', 'enterprise-ajax-cache'), esc_html($cache_class)) . '</p>';
                             }
                         } else {
                             echo '<p style="color:red;">' . esc_html__('External Object Cache enabled, but global $wp_object_cache not found.', 'enterprise-ajax-cache') . '</p>';
                         }
                    } else {
                         echo '<p style="color:red;">' . esc_html__('Memcached selected, but WordPress external object cache is not active.', 'enterprise-ajax-cache') . '</p>';
                    }
                    break;

                case 'transients':
                default:
                    global $wpdb;
                    $transient_prefix = '_transient_' . AJAX_CACHE_TRANSIENT_PREFIX;
                    $transient_like = $wpdb->esc_like($transient_prefix) . '%';
                    $count_sql = $wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s", $transient_like);
                    $transients_count = $wpdb->get_var($count_sql);

                    echo '<p>' . sprintf(esc_html__('Currently using WordPress transients. Found approximately %s relevant transient rows in the options table.', 'enterprise-ajax-cache'), esc_html(number_format_i18n($transients_count))) . '</p>';
                    if (wp_using_ext_object_cache()) {
                        echo '<p style="color: #0073aa;">' . __('Note: An external object cache is active, so transients might be stored there instead of the database.', 'enterprise-ajax-cache') . '</p>';
                    } else {
                        echo '<p style="color: orange;">' . __('Warning: Using database transients can be slow on high-traffic sites. Consider using Redis or Memcached for better performance.', 'enterprise-ajax-cache') . '</p>';
                    }
                    break;
            }
            ?>
        </div>

        <?php
    }
    private function render_logs_tab() {
         $settings = $this->get_settings();
         $log_destination = $settings['log_destination'];
         ?>
         <div class="card">
             <h3><?php esc_html_e('Log Viewer', 'enterprise-ajax-cache'); ?></h3>
             <p><strong><?php esc_html_e('Current Log Destination:', 'enterprise-ajax-cache'); ?></strong> <?php echo esc_html($this->get_log_destination_options()[$log_destination]); ?></p>

             <?php
             switch ($log_destination) {
                 case 'database':
                     $logs = get_option(AJAX_CACHE_LOG_OPTION, array());
                     $max_view = 100; // Limit how many entries to show in admin UI
                     $log_count = count($logs);
                     $logs_to_show = array_slice($logs, 0, $max_view);

                     echo '<p>' . sprintf(esc_html__('Showing the latest %1$d of %2$d stored log entries.', 'enterprise-ajax-cache'), count($logs_to_show), esc_html(number_format_i18n($log_count))) . '</p>';

                     if (empty($logs_to_show)) {
                         echo '<p><em>' . esc_html__('No log entries found in the database.', 'enterprise-ajax-cache') . '</em></p>';
                     } else {
                         ?>
                         <table class="wp-list-table widefat striped fixed" style="margin-top: 15px;">
                             <thead>
                                 <tr>
                                     <th style="width:160px;"><?php esc_html_e('Timestamp', 'enterprise-ajax-cache'); ?></th>
                                     <th style="width:80px;"><?php esc_html_e('Level', 'enterprise-ajax-cache'); ?></th>
                                     <th><?php esc_html_e('Message', 'enterprise-ajax-cache'); ?></th>
                                     <th style="width:30%;"><?php esc_html_e('Context', 'enterprise-ajax-cache'); ?></th>
                                 </tr>
                             </thead>
                             <tbody>
                                 <?php foreach ($logs_to_show as $log) :
                                    // Basic validation of log entry structure
                                    $timestamp = $log['timestamp'] ?? 'N/A';
                                    $level = $log['level'] ?? 'UNKNOWN';
                                    $message = $log['message'] ?? 'N/A';
                                    $context = $log['context'] ?? [];
                                    $time_obj = strtotime($timestamp);
                                 ?>
                                     <tr>
                                         <td><?php echo $time_obj ? esc_html(wp_date(get_option('date_format') . ' H:i:s', $time_obj)) : esc_html($timestamp); ?></td>
                                         <td><span class="log-level log-level-<?php echo esc_attr(strtolower($level)); ?>"><?php echo esc_html($level); ?></span></td>
                                         <td><?php echo esc_html($message); ?></td>
                                         <td>
                                             <?php if (!empty($context)) : ?>
                                                 <pre style="font-size: smaller; white-space: pre-wrap; word-break: break-all; max-height: 100px; overflow: auto; background: #f9f9f9; padding: 3px;"><?php echo esc_html(wp_json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)); ?></pre>
                                             <?php endif; ?>
                                         </td>
                                     </tr>
                                 <?php endforeach; ?>
                             </tbody>
                         </table>
                         <?php if ($log_count > 0) : ?>
                         <p style="margin-top: 15px;">
                             <?php
                             $clear_logs_url = add_query_arg(array(
                                 'action' => 'ajax_cache_clear_logs',
                                 '_wpnonce' => wp_create_nonce('clear_ajax_cache_logs')
                             ), admin_url('admin.php')); // Use admin.php for admin_action_*
                             ?>
                             <a href="<?php echo esc_url($clear_logs_url); ?>" class="button button-secondary" onclick="return confirm('<?php echo esc_js(__('Are you sure you want to clear all database logs?', 'enterprise-ajax-cache')); ?>');">
                                 <?php esc_html_e('Clear Database Logs', 'enterprise-ajax-cache'); ?>
                             </a>
                         </p>
                         <?php endif; ?>
                         <?php
                     }
                     break;

                 case 'file':
                     $log_file = $settings['log_file_path'];
                     echo '<p>' . sprintf(esc_html__('Attempting to read log file: %s', 'enterprise-ajax-cache'), '<code>' . esc_html($log_file) . '</code>') . '</p>';

                     if (!empty($log_file) && file_exists($log_file)) {
                         if (is_readable($log_file)) {
                             // Read only the last part of the file for performance
                             $file_size = filesize($log_file);
                             $max_read_bytes = 1024 * 256; // Read last 256KB max
                             $offset = max(0, $file_size - $max_read_bytes);
                             $log_content = file_get_contents($log_file, false, null, $offset);

                             if ($log_content === false) {
                                  echo '<p class="notice notice-error">' . esc_html__('Could not read log file content.', 'enterprise-ajax-cache') . '</p>';
                             } elseif (empty($log_content)) {
                                 echo '<p><em>' . esc_html__('Log file is empty.', 'enterprise-ajax-cache') . '</em></p>';
                             } else {
                                 if ($offset > 0) {
                                     echo '<p><em>' . sprintf(esc_html__('Showing last %s of log file.', 'enterprise-ajax-cache'), esc_html(size_format($max_read_bytes))) . '</em></p>';
                                 }
                                 echo '<pre style="background: #f9f9f9; border: 1px solid #ccc; padding: 10px; max-height: 500px; overflow-y: scroll; white-space: pre-wrap; word-break: break-all;">' . esc_html($log_content) . '</pre>';

                                  if (is_writable($log_file)) {
                                     $clear_file_url = add_query_arg(array(
                                         'action' => 'ajax_cache_clear_log_file',
                                         '_wpnonce' => wp_create_nonce('clear_ajax_cache_log_file')
                                     ), admin_url('admin.php'));
                                     ?>
                                     <p style="margin-top: 15px;">
                                         <a href="<?php echo esc_url($clear_file_url); ?>" class="button button-secondary" onclick="return confirm('<?php echo esc_js(__('Are you sure you want to clear the log file?', 'enterprise-ajax-cache')); ?>');">
                                             <?php esc_html_e('Clear Log File', 'enterprise-ajax-cache'); ?>
                                         </a>
                                     </p>
                                     <?php
                                  } else {
                                       echo '<p class="notice notice-warning">' . esc_html__('Log file is not writable. Cannot clear file from here.', 'enterprise-ajax-cache') . '</p>';
                                  }
                             }
                         } else {
                             echo '<p class="notice notice-error">' . esc_html__('Log file exists but is not readable by the web server.', 'enterprise-ajax-cache') . '</p>';
                         }
                     } else {
                         echo '<p><em>' . esc_html__('Log file does not exist at the specified path.', 'enterprise-ajax-cache') . '</em></p>';
                     }
                     break;

                 case 'wp_debug':
                 default:
                     $debug_log_path = defined('WP_DEBUG_LOG') && is_string(WP_DEBUG_LOG) ? WP_DEBUG_LOG : WP_CONTENT_DIR . '/debug.log';
                     echo '<p>' . sprintf(
                        wp_kses(__('Logs are being written to the WordPress debug log file (%s).', 'enterprise-ajax-cache'), ['code' => []]),
                        '<code>' . esc_html($debug_log_path) . '</code>'
                     ) . '</p>';
                     if (!(defined('WP_DEBUG') && WP_DEBUG && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG)) {
                         echo '<p class="notice notice-warning">' . sprintf(
                             wp_kses(__('Warning: %1$s and %2$s must be enabled in %3$s for logs to be written.', 'enterprise-ajax-cache'), ['code' => []]),
                             '<code>WP_DEBUG</code>', '<code>WP_DEBUG_LOG</code>', '<code>wp-config.php</code>'
                         ) . '</p>';
                     }
                     echo '<p>' . esc_html__('You need to access this file directly on your server to view the logs.', 'enterprise-ajax-cache') . '</p>';
                     break;
             }
             ?>
             <style>
                .log-level-error { color: #dc3232; font-weight: bold; text-transform: uppercase; }
                .log-level-warning { color: #ffb900; font-weight: bold; text-transform: uppercase; }
                .log-level-info { color: #0073aa; text-transform: uppercase; }
                .log-level-debug { color: #777; text-transform: uppercase; }
             </style>
         </div>
         <?php
    }
     private function render_tools_tab() {
         ?>
         <div class="card">
             <h3><?php esc_html_e('Manual Cache Clearing', 'enterprise-ajax-cache'); ?></h3>

             <form method="post" action="<?php echo esc_url(admin_url('tools.php?page=enterprise-ajax-cache&tab=tools')); ?>" style="margin-bottom: 20px; padding-bottom: 20px; border-bottom: 1px solid #eee;">
                 <input type="hidden" name="action" value="clear_all_caches">
                 <?php wp_nonce_field('ajax_cache_clear_all', 'ajax_cache_clear_all_nonce'); ?>
                 <p><?php esc_html_e('Immediately clear all cached AJAX responses managed by this plugin.', 'enterprise-ajax-cache'); ?></p>
                 <p><?php submit_button(__('Clear All Caches', 'enterprise-ajax-cache'), 'primary', 'submit_clear_all', false); ?></p>
             </form>

             <form method="post" action="<?php echo esc_url(admin_url('tools.php?page=enterprise-ajax-cache&tab=tools')); ?>">
                 <input type="hidden" name="action" value="clear_specific_cache">
                 <?php wp_nonce_field('ajax_cache_clear_specific', 'ajax_cache_clear_specific_nonce'); ?>
                 <p><?php esc_html_e('Clear cache only for a specific AJAX action.', 'enterprise-ajax-cache'); ?></p>
                 <?php
                 $settings = $this->get_settings();
                 $cacheable_actions = $settings['cacheable_actions'];
                 if (empty($cacheable_actions)) : ?>
                    <p><em><?php esc_html_e('No actions are configured for caching yet.', 'enterprise-ajax-cache'); ?></em></p>
                 <?php else : ?>
                     <label for="cache_action_select" class="screen-reader-text"><?php esc_html_e('Select action to clear:', 'enterprise-ajax-cache'); ?></label>
                     <select name="cache_action" id="cache_action_select" style="min-width: 200px;">
                         <?php foreach ($cacheable_actions as $action) : ?>
                             <option value="<?php echo esc_attr($action); ?>"><?php echo esc_html($action); ?></option>
                         <?php endforeach; ?>
                     </select>
                     <?php submit_button(__('Clear Selected Cache', 'enterprise-ajax-cache'), 'secondary', 'submit_clear_specific', false); ?>
                      <p class="description"><?php esc_html_e('Note: Due to current limitations, this will clear ALL caches, same as the button above.', 'enterprise-ajax-cache'); ?></p>
                 <?php endif; ?>
             </form>
         </div>

        <div class="card">
             <h3><?php esc_html_e('Import / Export Settings', 'enterprise-ajax-cache'); ?></h3>
             <div style="display: flex; gap: 30px; flex-wrap: wrap;">
                 <div style="flex: 1; min-width: 250px;">
                     <h4><?php esc_html_e('Export', 'enterprise-ajax-cache'); ?></h4>
                     <p><?php esc_html_e('Download the current plugin settings as a JSON file.', 'enterprise-ajax-cache'); ?></p>
                     <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                         <input type="hidden" name="action" value="ajax_cache_export_settings">
                         <?php wp_nonce_field('ajax_cache_export_settings', 'ajax_cache_export_nonce'); ?>
                         <?php submit_button(__('Export Settings', 'enterprise-ajax-cache'), 'secondary', 'submit_export', false); ?>
                     </form>
                 </div>
                 <div style="flex: 1; min-width: 250px;">
                     <h4><?php esc_html_e('Import', 'enterprise-ajax-cache'); ?></h4>
                     <p><?php esc_html_e('Upload a JSON file to restore plugin settings. Current settings will be overwritten.', 'enterprise-ajax-cache'); ?></p>
                     <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" enctype="multipart/form-data">
                         <input type="hidden" name="action" value="ajax_cache_import_settings">
                         <?php wp_nonce_field('ajax_cache_import_settings', 'ajax_cache_import_nonce'); ?>
                         <p>
                             <label for="settings_file" class="screen-reader-text"><?php esc_html_e('Select JSON file to import:', 'enterprise-ajax-cache'); ?></label>
                             <input type="file" name="settings_file" id="settings_file" accept=".json,application/json">
                         </p>
                         <?php submit_button(__('Import Settings', 'enterprise-ajax-cache'), 'secondary', 'submit_import', false); ?>
                     </form>
                 </div>
             </div>
         </div>
         <?php
    }
} // END class Enterprise_AJAX_Cache_Settings
