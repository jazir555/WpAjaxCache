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
define('AJAX_CACHE_SETTINGS_KEY', 'enterprise_ajax_cache_settings');

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
	private $settings;

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
		// Initialize logger
		$this->logger = Ajax_Cache_Logger::get_instance();

		// Initialize settings
		$this->settings = new Enterprise_AJAX_Cache_Settings($this);

		// Get plugin settings
		$this->plugin_settings = $this->settings->get_settings();

		// Set up hooks
		$this->setup_hooks();
	}

	/**
	 * Set up plugin hooks
	 */
	private function setup_hooks() {
		// Check compatibility on admin side
		add_action('admin_notices', [$this, 'compatibility_notices']);
		add_action('admin_notices', [$this, 'activation_error_notice']);

		// AJAX handling
		add_action('admin_init', [$this, 'init_ajax_caching']);

		// Post update handling
		add_action('save_post', [$this, 'invalidate_cache_on_post_save']);

		// Register activation/deactivation hooks
		register_activation_hook(__FILE__, [$this, 'activate']);
		register_deactivation_hook(__FILE__, [$this, 'deactivate']);

		// Add debug headers
		add_action('send_headers', [$this, 'add_debug_headers']);

		// Set up auto purge
		$this->setup_auto_purge();

		// Apply settings to filters
		$this->apply_settings();
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
		return $this->settings;
	}

	/**
	 * Get plugin settings
	 *
	 * @return array
	 */
	public function get_plugin_settings() {
		return $this->plugin_settings;
	}

	/**
	 * Check system compatibility
	 *
	 * @return array Compatibility status and issues
	 */
	public function check_compatibility() {
		$issues = array();
		$compatible = true;
		$logger = $this->logger;

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
	public function compatibility_notices() {
		$check = $this->check_compatibility();

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

	/**
	 * Display activation error notice
	 */
	public function activation_error_notice() {
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

	/**
	 * Initialize AJAX caching
	 */
	public function init_ajax_caching() {
		$logger = $this->logger;
		$settings = $this->plugin_settings;

		// Skip if caching is disabled
		if (!$settings['enabled']) {
			return;
		}

		if (defined('DOING_AJAX') && DOING_AJAX && isset($_REQUEST['action'])) {
			$action = sanitize_key($_REQUEST['action']);
			$logger->debug("Processing AJAX request for action: {$action}");

			// Check if the action is cacheable
			if ($this->is_cacheable_action($action)) {
				$logger->debug("Action {$action} is cacheable");
				$cache_key = $this->generate_cache_key($action);
				$cached_response = $this->get_cached_response($cache_key);

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
							$this->cache_response($cache_key, $output);
						}
						return $output;
					});
				}
			}
		}
	}

	/**
	 * Determine if an AJAX action is cacheable
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

		// Check if this action is in the list of cacheable actions
		return in_array($action, $settings['cacheable_actions'], true);
	}

	/**
	 * Generate a unique cache key based on request and context
	 *
	 * @param string $action The AJAX action name
	 * @return string The cache key
	 */
	public function generate_cache_key($action) {
		$settings = $this->plugin_settings;
		$logger = $this->logger;

		$key_parts = [$action];

		// Include specified request parameters
		if (isset($settings['cache_key_params'][$action])) {
			$params = $settings['cache_key_params'][$action];
			foreach ($params as $param) {
				if (isset($_REQUEST[$param])) {
					$key_parts[] = $param . '=' . sanitize_text_field($_REQUEST[$param]);
				}
			}
		}

		// Include user-specific factors
		if ($settings['cache_key_factors']['user_id']) {
			$key_parts[] = 'user_id=' . get_current_user_id();
		}

		if ($settings['cache_key_factors']['user_roles']) {
			$user = wp_get_current_user();
			$roles = $user->roles ? $user->roles : ['none'];
			sort($roles);
			$key_parts[] = 'user_roles=' . implode(',', $roles);
		}

		// Include specified cookies
		if (isset($settings['cache_key_cookies'][$action])) {
			$cookies = $settings['cache_key_cookies'][$action];
			foreach ($cookies as $cookie) {
				if (isset($_COOKIE[$cookie])) {
					$key_parts[] = $cookie . '=' . sanitize_text_field($_COOKIE[$cookie]);
				}
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
	public function get_cached_response($cache_key) {
		$logger = $this->logger;
		$settings = $this->plugin_settings;
		$full_key = 'ajax_cache_' . $cache_key;

		$stats = get_option('ajax_cache_stats', array(
			'hits' => 0,
			'misses' => 0,
			'sets' => 0,
			'purges' => 0,
			'last_purge' => 0
		));

		try {
			$backend = $settings['cache_backend'];

			// Use Redis if selected and available
			if ($backend === 'redis' && function_exists('wp_redis') && defined('WP_REDIS_ENABLED') && WP_REDIS_ENABLED) {
				$logger->debug("Attempting to get cache from Redis", array('key' => $full_key));
				$cached = wp_redis()->get($full_key);

				if ($cached !== false) {
					$stats['hits']++;
					update_option('ajax_cache_stats', $stats);
					return $cached;
				}
			}

			// Use Memcached if selected and available
			if ($backend === 'memcached' && class_exists('WP_Object_Cache') && isset($GLOBALS['wp_object_cache']) &&
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
	public function cache_response($cache_key, $response) {
		$logger = $this->logger;
		$settings = $this->plugin_settings;

		$stats = get_option('ajax_cache_stats', array(
			'hits' => 0,
			'misses' => 0,
			'sets' => 0,
			'purges' => 0,
			'last_purge' => 0
		));

		try {
			$full_key = 'ajax_cache_' . $cache_key;

			// Get expiration time - first check per-action settings, then default
			$action = '';
			if (preg_match('/^([a-z0-9_]+)/', $cache_key, $matches)) {
				$action = $matches[1];
			}

			$expiration = isset($settings['per_action_expiration'][$action])
				? $settings['per_action_expiration'][$action]
				: $settings['default_expiration'];

			$backend = $settings['cache_backend'];

			// Use Redis if selected and available
			if ($backend === 'redis' && function_exists('wp_redis') && defined('WP_REDIS_ENABLED') && WP_REDIS_ENABLED) {
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

			// Use Memcached if selected and available
			if ($backend === 'memcached' && class_exists('WP_Object_Cache') && isset($GLOBALS['wp_object_cache']) &&
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
	 * @return int Number of entries purged
	 */
	public function purge_cache_by_action($action) {
		global $wpdb;
		$logger = $this->logger;
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
				if (delete_transient(str_replace('_transient_', '', $key))) {
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
	 *
	 * @return int Number of entries purged
	 */
	public function purge_all_caches() {
		global $wpdb;
		$logger = $this->logger;
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
				if (delete_transient(str_replace('_transient_', '', $key))) {
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
	 * Automatically invalidate caches when posts are updated
	 *
	 * @param int $post_id The ID of the post being saved
	 */
	public function invalidate_cache_on_post_save($post_id) {
		$logger = $this->logger;
		$settings = $this->plugin_settings;

		// Don't run on autosave
		if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
			return;
		}

		// Check if the post type should trigger invalidation
		$post_type = get_post_type($post_id);
		$post_types_to_watch = $settings['watched_post_types'];

		if (in_array($post_type, $post_types_to_watch, true)) {
			$logger->info("Post update detected for type {$post_type}, checking cache invalidation", array('post_id' => $post_id));

			$actions_to_invalidate = isset($settings['invalidation_rules'][$post_type])
				? $settings['invalidation_rules'][$post_type]
				: [];

			if (!empty($actions_to_invalidate)) {
				$logger->info("Actions to invalidate: " . implode(', ', $actions_to_invalidate));

				foreach ($actions_to_invalidate as $action) {
					$this->purge_cache_by_action($action);
				}
			}
		}
	}

	/**
	 * Add debug headers to AJAX responses when debug mode is enabled
	 */
	public function add_debug_headers() {
		$settings = $this->plugin_settings;

		if (!$settings['debug_mode'] || !defined('DOING_AJAX') || !DOING_AJAX) {
			return;
		}

		$action = isset($_REQUEST['action']) ? sanitize_key($_REQUEST['action']) : '';

		if (empty($action)) {
			return;
		}

		if (in_array($action, $settings['cacheable_actions'], true)) {
			$cache_key = $this->generate_cache_key($action);
			$cached = $this->get_cached_response($cache_key) !== false;

			header('X-AJAX-Cache: enabled');
			header('X-AJAX-Cache-Action: ' . $action);
			header('X-AJAX-Cache-Key: ' . $cache_key);
			header('X-AJAX-Cache-Hit: ' . ($cached ? 'true' : 'false'));

			if ($cached) {
				header('X-AJAX-Cache-Served-From: ' . $settings['cache_backend']);
			}
		} else {
			header('X-AJAX-Cache: disabled');
			header('X-AJAX-Cache-Action: ' . $action);
		}
	}

	/**
	 * Setup automatic cache purging based on schedule
	 */
	public function setup_auto_purge() {
		$settings = $this->plugin_settings;
		$schedule = $settings['auto_purge_schedule'];

		// Clear any existing scheduled event
		if (wp_next_scheduled('ajax_cache_auto_purge')) {
			wp_clear_scheduled_hook('ajax_cache_auto_purge');
		}

		// Schedule new event if not set to "never"
		if ($schedule !== 'never') {
			if (!wp_next_scheduled('ajax_cache_auto_purge')) {
				wp_schedule_event(time(), $schedule, 'ajax_cache_auto_purge');
			}
		}

		// Add action for auto purge event
		add_action('ajax_cache_auto_purge', [$this, 'do_auto_purge']);
	}

	/**
	 * Automatic cache purge event callback
	 */
	public function do_auto_purge() {
		$logger = $this->logger;
		$logger->info('Running scheduled cache purge');

		$count = $this->purge_all_caches();

		$logger->info(sprintf('Automatic purge completed, removed %d cache entries', $count));
	}

	/**
	 * Apply settings to filters
	 */
	public function apply_settings() {
		$settings = $this->plugin_settings;

		// Apply log level
		add_filter('ajax_cache_log_level', function($level) use ($settings) {
			return $settings['log_level'];
		});

		// Apply cacheable actions
		add_filter('ajax_cacheable_actions', function($actions) use ($settings) {
			return $settings['cacheable_actions'];
		});

		// Apply cache key parameters
		add_filter('ajax_cache_key_params', function($params, $action) use ($settings) {
			if (isset($settings['cache_key_params'][$action])) {
				return $settings['cache_key_params'][$action];
			}
			return $params;
		}, 10, 2);

		// Apply cache key factors
		add_filter('ajax_cache_key_factors', function($factors, $action) use ($settings) {
			$global_factors = array();

			if ($settings['cache_key_factors']['user_id']) {
				$global_factors[] = 'user_id';
			}

			if ($settings['cache_key_factors']['user_roles']) {
				$global_factors[] = 'user_roles';
			}

			return $global_factors;
		}, 10, 2);

		// Apply cache key cookies
		add_filter('ajax_cache_key_cookies', function($cookies, $action) use ($settings) {
			if (isset($settings['cache_key_cookies'][$action])) {
				return $settings['cache_key_cookies'][$action];
			}
			return $cookies;
		}, 10, 2);

		// Apply cache expiration
		add_filter('ajax_cache_expiration', function($expiration, $cache_key) use ($settings) {
			// Extract action from cache key if possible
			$action = '';
			if (preg_match('/^[a-f0-9]+_(.+)$/', $cache_key, $matches)) {
				$action = $matches[1];
			}

			// Check for per-action expiration
			if ($action && isset($settings['per_action_expiration'][$action])) {
				return $settings['per_action_expiration'][$action];
			}

			// Fall back to default expiration
			return $settings['default_expiration'];
		}, 10, 2);

		// Apply watched post types
		add_filter('ajax_cache_watched_post_types', function($post_types) use ($settings) {
			return $settings['watched_post_types'];
		});

		// Apply invalidation rules
		add_filter('ajax_cache_invalidate_on_post_save', function($actions, $post_id, $post_type) use ($settings) {
			if (isset($settings['invalidation_rules'][$post_type])) {
				return $settings['invalidation_rules'][$post_type];
			}
			return $actions;
		}, 10, 3);
	}

	/**
	 * Plugin activation hook
	 */
	public function activate() {
		$logger = $this->logger;
		$logger->info("Plugin activation started");

		$check = $this->check_compatibility();

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

	/**
	 * Plugin deactivation hook
	 */
	public function deactivate() {
		$logger = $this->logger;
		$logger->info("Plugin deactivation started");

		// Clean up on deactivation
		$this->purge_all_caches();

		$logger->info("Plugin deactivated successfully");
	}

	/**
	 * Plugin uninstall hook
	 */
	public static function uninstall() {
		// Clean up options
		delete_option('ajax_cache_activated');
		delete_option('ajax_cache_version');
		delete_option('ajax_cache_stats');
		delete_option(AJAX_CACHE_SETTINGS_KEY);

		// Remove all caches
		$instance = self::get_instance();
		$instance->purge_all_caches();
	}

	/**
	 * Add example hooks for WooCommerce
	 */
	public function add_example_hooks() {
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
	}
}

/**
 * Settings class for Enterprise AJAX Cache
 */
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
	$this->defaults = $this->get_default_settings();

	// Register settings page in admin menu
	add_action('admin_menu', [$this, 'add_admin_menu']);

	// Register settings
	add_action('admin_init', [$this, 'register_settings']);

	// Handle import/export
	add_action('admin_post_ajax_cache_export_settings', [$this, 'export_settings']);
	add_action('admin_post_ajax_cache_import_settings', [$this, 'import_settings']);

	// Reset statistics
	add_action('admin_init', [$this, 'reset_statistics']);

	// Admin notices for import/export
	add_action('admin_notices', [$this, 'admin_notices']);
}

/**
 * Get default settings
 *
 * @return array Default settings
 */
public function get_default_settings() {
	return array(
		'enabled' => true,
		'debug_mode' => false,
		'log_level' => Ajax_Cache_Logger::LOG_ERROR,
		'log_destination' => 'wp_debug',
		'log_max_entries' => 1000,
		'cache_backend' => 'transients',
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
		'default_expiration' => 3600, // 1 hour
		'per_action_expiration' => array(),
		'cacheable_actions' => array(),
		'cache_key_params' => array(),
		'cache_key_factors' => array(
			'user_id' => false,
			'user_roles' => false,
		),
		'cache_key_cookies' => array(),
		'watched_post_types' => array('post', 'page'),
		'invalidation_rules' => array(),
		'auto_purge_schedule' => 'never',
	);
}

/**
 * Get plugin settings
 *
 * @return array Plugin settings
 */
public function get_settings() {
	$settings = get_option(AJAX_CACHE_SETTINGS_KEY, array());
	return wp_parse_args($settings, $this->defaults);
}

/**
 * Register the plugin settings page
 */
public function add_admin_menu() {
	add_management_page(
		__('Enterprise AJAX Cache', 'enterprise-ajax-cache'),
		__('AJAX Cache', 'enterprise-ajax-cache'),
		'manage_options',
		'enterprise-ajax-cache',
		[$this, 'render_settings_page']
	);
}

/**
 * Register settings and fields
 */
public function register_settings() {
	// Register the settings
	register_setting(
		'ajax_cache_settings',             // Option group
		AJAX_CACHE_SETTINGS_KEY,           // Option name
		[$this, 'sanitize_settings']       // Sanitize callback
	);

	// SECTION: General Settings
	add_settings_section(
		'ajax_cache_general_section',      // ID
		__('General Settings', 'enterprise-ajax-cache'),  // Title
		[$this, 'general_section_callback'], // Callback
		'ajax_cache_settings'              // Page
	);

	add_settings_field(
		'ajax_cache_enabled',              // ID
		__('Enable AJAX Caching', 'enterprise-ajax-cache'), // Title
		[$this, 'enabled_callback'],     // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_general_section'       // Section
	);

	add_settings_field(
		'debug_mode',                      // ID
		__('Debug Mode', 'enterprise-ajax-cache'), // Title
		[$this, 'debug_mode_callback'],  // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_general_section'       // Section
	);

	// SECTION: Logging Settings
	add_settings_section(
		'ajax_cache_logging_section',      // ID
		__('Logging Settings', 'enterprise-ajax-cache'), // Title
		[$this, 'logging_section_callback'], // Callback
		'ajax_cache_settings'              // Page
	);

	add_settings_field(
		'log_level',                       // ID
		__('Log Level', 'enterprise-ajax-cache'), // Title
		[$this, 'log_level_callback'],   // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_logging_section'       // Section
	);

	add_settings_field(
		'log_destination',                 // ID
		__('Log Destination', 'enterprise-ajax-cache'), // Title
		[$this, 'log_destination_callback'], // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_logging_section'       // Section
	);

	add_settings_field(
		'log_max_entries',                 // ID
		__('Maximum Log Entries', 'enterprise-ajax-cache'), // Title
		[$this, 'log_max_entries_callback'], // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_logging_section'       // Section
	);

	// SECTION: Cache Storage
	add_settings_section(
		'ajax_cache_storage_section',      // ID
		__('Cache Storage Settings', 'enterprise-ajax-cache'), // Title
		[$this, 'storage_section_callback'], // Callback
		'ajax_cache_settings'              // Page
	);

	add_settings_field(
		'cache_backend',                   // ID
		__('Cache Backend', 'enterprise-ajax-cache'), // Title
		[$this, 'backend_callback'],     // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_storage_section'       // Section
	);

	add_settings_field(
		'redis_settings',                  // ID
		__('Redis Settings', 'enterprise-ajax-cache'), // Title
		[$this, 'redis_settings_callback'], // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_storage_section'       // Section
	);

	add_settings_field(
		'memcached_settings',              // ID
		__('Memcached Settings', 'enterprise-ajax-cache'), // Title
		[$this, 'memcached_settings_callback'], // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_storage_section'       // Section
	);

	// SECTION: Cache Expiration
	add_settings_section(
		'ajax_cache_expiration_section',   // ID
		__('Cache Expiration Settings', 'enterprise-ajax-cache'), // Title
		[$this, 'expiration_section_callback'], // Callback
		'ajax_cache_settings'              // Page
	);

	add_settings_field(
		'default_expiration',              // ID
		__('Default Expiration (seconds)', 'enterprise-ajax-cache'), // Title
		[$this, 'default_expiration_callback'], // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_expiration_section'    // Section
	);

	add_settings_field(
		'per_action_expiration',           // ID
		__('Per-Action Expiration', 'enterprise-ajax-cache'), // Title
		[$this, 'per_action_expiration_callback'], // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_expiration_section'    // Section
	);

	// SECTION: Cache Actions Configuration
	add_settings_section(
		'ajax_cache_actions_section',      // ID
		__('Cacheable Actions Settings', 'enterprise-ajax-cache'), // Title
		[$this, 'actions_section_callback'], // Callback
		'ajax_cache_settings'              // Page
	);

	add_settings_field(
		'cacheable_actions',               // ID
		__('Cacheable AJAX Actions', 'enterprise-ajax-cache'), // Title
		[$this, 'cacheable_actions_callback'], // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_actions_section'       // Section
	);

	// SECTION: Cache Key Configuration
	add_settings_section(
		'ajax_cache_key_section',          // ID
		__('Cache Key Settings', 'enterprise-ajax-cache'), // Title
		[$this, 'key_section_callback'], // Callback
		'ajax_cache_settings'              // Page
	);

	add_settings_field(
		'cache_key_params',                // ID
		__('Request Parameters for Cache Key', 'enterprise-ajax-cache'), // Title
		[$this, 'key_params_callback'],  // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_key_section'           // Section
	);

	add_settings_field(
		'cache_key_factors',               // ID
		__('User Factors for Cache Key', 'enterprise-ajax-cache'), // Title
		[$this, 'key_factors_callback'], // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_key_section'           // Section
	);

	add_settings_field(
		'cache_key_cookies',               // ID
		__('Cookies for Cache Key', 'enterprise-ajax-cache'), // Title
		[$this, 'key_cookies_callback'], // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_key_section'           // Section
	);

	// SECTION: Cache Invalidation
	add_settings_section(
		'ajax_cache_invalidation_section', // ID
		__('Cache Invalidation Settings', 'enterprise-ajax-cache'), // Title
		[$this, 'invalidation_section_callback'], // Callback
		'ajax_cache_settings'              // Page
	);

	add_settings_field(
		'watched_post_types',              // ID
		__('Post Types to Watch', 'enterprise-ajax-cache'), // Title
		[$this, 'watched_post_types_callback'], // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_invalidation_section'  // Section
	);

	add_settings_field(
		'invalidation_rules',              // ID
		__('Invalidation Rules', 'enterprise-ajax-cache'), // Title
		[$this, 'invalidation_rules_callback'], // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_invalidation_section'  // Section
	);

	add_settings_field(
		'auto_purge_schedule',             // ID
		__('Automatic Purge Schedule', 'enterprise-ajax-cache'), // Title
		[$this, 'auto_purge_schedule_callback'], // Callback
		'ajax_cache_settings',             // Page
		'ajax_cache_invalidation_section'  // Section
	);
}

/**
 * Sanitize settings
 *
 * @param array $input Raw input data
 * @return array Sanitized settings
 */
public function sanitize_settings($input) {
	$sanitized = array();

	// General Settings
	$sanitized['enabled'] = isset($input['enabled']) ? (bool) $input['enabled'] : $this->defaults['enabled'];
	$sanitized['debug_mode'] = isset($input['debug_mode']) ? (bool) $input['debug_mode'] : $this->defaults['debug_mode'];

	// Logging Settings
	$log_level = isset($input['log_level']) ? intval($input['log_level']) : $this->defaults['log_level'];
	$sanitized['log_level'] = in_array($log_level, array(
		Ajax_Cache_Logger::LOG_NONE,
		Ajax_Cache_Logger::LOG_ERROR,
		Ajax_Cache_Logger::LOG_WARNING,
		Ajax_Cache_Logger::LOG_INFO,
		Ajax_Cache_Logger::LOG_DEBUG
	)) ? $log_level : $this->defaults['log_level'];

	$log_destination = isset($input['log_destination']) ? sanitize_text_field($input['log_destination']) : $this->defaults['log_destination'];
	$sanitized['log_destination'] = in_array($log_destination, array('wp_debug', 'database', 'file')) ? $log_destination : $this->defaults['log_destination'];

	$sanitized['log_max_entries'] = isset($input['log_max_entries']) ? intval($input['log_max_entries']) : $this->defaults['log_max_entries'];
	if ($sanitized['log_max_entries'] < 10) {
		$sanitized['log_max_entries'] = 10;
	}

	// Cache Storage Settings
	$cache_backend = isset($input['cache_backend']) ? sanitize_text_field($input['cache_backend']) : $this->defaults['cache_backend'];
	$sanitized['cache_backend'] = in_array($cache_backend, array('transients', 'redis', 'memcached')) ? $cache_backend : $this->defaults['cache_backend'];

	if (isset($input['redis_settings']) && is_array($input['redis_settings'])) {
		$sanitized['redis_settings'] = array(
			'host' => isset($input['redis_settings']['host']) ? sanitize_text_field($input['redis_settings']['host']) : $this->defaults['redis_settings']['host'],
			'port' => isset($input['redis_settings']['port']) ? intval($input['redis_settings']['port']) : $this->defaults['redis_settings']['port'],
			'auth' => isset($input['redis_settings']['auth']) ? sanitize_text_field($input['redis_settings']['auth']) : $this->defaults['redis_settings']['auth'],
			'database' => isset($input['redis_settings']['database']) ? intval($input['redis_settings']['database']) : $this->defaults['redis_settings']['database'],
		);
	} else {
		$sanitized['redis_settings'] = $this->defaults['redis_settings'];
	}

	if (isset($input['memcached_settings']) && is_array($input['memcached_settings'])) {
		$sanitized['memcached_settings'] = array(
			'host' => isset($input['memcached_settings']['host']) ? sanitize_text_field($input['memcached_settings']['host']) : $this->defaults['memcached_settings']['host'],
			'port' => isset($input['memcached_settings']['port']) ? intval($input['memcached_settings']['port']) : $this->defaults['memcached_settings']['port'],
		);
	} else {
		$sanitized['memcached_settings'] = $this->defaults['memcached_settings'];
	}

	// Cache Expiration Settings
	$sanitized['default_expiration'] = isset($input['default_expiration']) ? intval($input['default_expiration']) : $this->defaults['default_expiration'];
	if ($sanitized['default_expiration'] < 60) {
		$sanitized['default_expiration'] = 60; // Minimum 1 minute
	}

	if (isset($input['per_action_expiration']) && is_array($input['per_action_expiration'])) {
		$sanitized['per_action_expiration'] = array();
		foreach ($input['per_action_expiration'] as $action => $expiration) {
			$action = sanitize_key($action);
			$expiration = intval($expiration);
			if ($expiration >= 60) { // Minimum 1 minute
				$sanitized['per_action_expiration'][$action] = $expiration;
			}
		}
	} else {
		$sanitized['per_action_expiration'] = $this->defaults['per_action_expiration'];
	}

	// Cacheable Actions Settings
	if (isset($input['cacheable_actions']) && is_array($input['cacheable_actions'])) {
		$sanitized['cacheable_actions'] = array();
		foreach ($input['cacheable_actions'] as $action) {
			$sanitized['cacheable_actions'][] = sanitize_key($action);
		}
	} else {
		$sanitized['cacheable_actions'] = $this->defaults['cacheable_actions'];
	}

	// Cache Key Settings
	if (isset($input['cache_key_params']) && is_array($input['cache_key_params'])) {
		$sanitized['cache_key_params'] = array();
		foreach ($input['cache_key_params'] as $action => $params) {
			$action = sanitize_key($action);
			if (is_array($params)) {
				$sanitized['cache_key_params'][$action] = array_map('sanitize_key', $params);
			}
		}
	} else {
		$sanitized['cache_key_params'] = $this->defaults['cache_key_params'];
	}

	if (isset($input['cache_key_factors'])) {
		$sanitized['cache_key_factors'] = array(
			'user_id' => isset($input['cache_key_factors']['user_id']) ? (bool) $input['cache_key_factors']['user_id'] : $this->defaults['cache_key_factors']['user_id'],
			'user_roles' => isset($input['cache_key_factors']['user_roles']) ? (bool) $input['cache_key_factors']['user_roles'] : $this->defaults['cache_key_factors']['user_roles'],
		);
	} else {
		$sanitized['cache_key_factors'] = $this->defaults['cache_key_factors'];
	}

	if (isset($input['cache_key_cookies']) && is_array($input['cache_key_cookies'])) {
		$sanitized['cache_key_cookies'] = array();
		foreach ($input['cache_key_cookies'] as $action => $cookies) {
			$action = sanitize_key($action);
			if (is_array($cookies)) {
				$sanitized['cache_key_cookies'][$action] = array_map('sanitize_key', $cookies);
			}
		}
	} else {
		$sanitized['cache_key_cookies'] = $this->defaults['cache_key_cookies'];
	}

	// Cache Invalidation Settings
	if (isset($input['watched_post_types']) && is_array($input['watched_post_types'])) {
		$sanitized['watched_post_types'] = array_map('sanitize_key', $input['watched_post_types']);
	} else {
		$sanitized['watched_post_types'] = $this->defaults['watched_post_types'];
	}

	if (isset($input['invalidation_rules']) && is_array($input['invalidation_rules'])) {
		$sanitized['invalidation_rules'] = array();
		foreach ($input['invalidation_rules'] as $post_type => $actions) {
			$post_type = sanitize_key($post_type);
			if (is_array($actions)) {
				$sanitized['invalidation_rules'][$post_type] = array_map('sanitize_key', $actions);
			}
		}
	} else {
		$sanitized['invalidation_rules'] = $this->defaults['invalidation_rules'];
	}

	$auto_purge_schedule = isset($input['auto_purge_schedule']) ? sanitize_key($input['auto_purge_schedule']) : $this->defaults['auto_purge_schedule'];
	$sanitized['auto_purge_schedule'] = in_array($auto_purge_schedule, array('never', 'hourly', 'twicedaily', 'daily', 'weekly')) ? $auto_purge_schedule : $this->defaults['auto_purge_schedule'];

	return $sanitized;
}

/**
 * Section callbacks
 */
public function general_section_callback() {
	echo '<p>' . __('Configure general plugin behavior and debug options.', 'enterprise-ajax-cache') . '</p>';
}

public function logging_section_callback() {
	echo '<p>' . __('Configure how and where log entries are stored.', 'enterprise-ajax-cache') . '</p>';
}

public function storage_section_callback() {
	echo '<p>' . __('Configure where cached data is stored.', 'enterprise-ajax-cache') . '</p>';
}

public function expiration_section_callback() {
	echo '<p>' . __('Configure how long cached data is kept before expiring.', 'enterprise-ajax-cache') . '</p>';
}

public function actions_section_callback() {
	echo '<p>' . __('Configure which AJAX actions should be cached.', 'enterprise-ajax-cache') . '</p>';
}

public function key_section_callback() {
	echo '<p>' . __('Configure how cache keys are generated.', 'enterprise-ajax-cache') . '</p>';
}

public function invalidation_section_callback() {
	echo '<p>' . __('Configure when caches should be automatically invalidated.', 'enterprise-ajax-cache') . '</p>';
}

/**
 * Field callbacks - General Section
 */
public function enabled_callback() {
	$settings = $this->get_settings();
	echo '<label><input type="checkbox" name="' . AJAX_CACHE_SETTINGS_KEY . '[enabled]" value="1" ' . checked(1, $settings['enabled'], false) . '/> ';
	echo __('Enable AJAX caching functionality', 'enterprise-ajax-cache') . '</label>';
	echo '<p class="description">' . __('Uncheck to temporarily disable all caching without deactivating the plugin.', 'enterprise-ajax-cache') . '</p>';
}

public function debug_mode_callback() {
	$settings = $this->get_settings();
	echo '<label><input type="checkbox" name="' . AJAX_CACHE_SETTINGS_KEY . '[debug_mode]" value="1" ' . checked(1, $settings['debug_mode'], false) . '/> ';
	echo __('Enable debug mode', 'enterprise-ajax-cache') . '</label>';
	echo '<p class="description">' . __('When enabled, adds debug headers to AJAX responses and increases logging detail.', 'enterprise-ajax-cache') . '</p>';
}

/**
 * Field callbacks - Logging Section
 */
public function log_level_callback() {
	$settings = $this->get_settings();

	$levels = array(
		Ajax_Cache_Logger::LOG_NONE => __('None (Disabled)', 'enterprise-ajax-cache'),
		Ajax_Cache_Logger::LOG_ERROR => __('Errors Only', 'enterprise-ajax-cache'),
		Ajax_Cache_Logger::LOG_WARNING => __('Warnings & Errors', 'enterprise-ajax-cache'),
		Ajax_Cache_Logger::LOG_INFO => __('Info, Warnings & Errors', 'enterprise-ajax-cache'),
		Ajax_Cache_Logger::LOG_DEBUG => __('Debug (All Messages)', 'enterprise-ajax-cache'),
	);

	echo '<select name="' . AJAX_CACHE_SETTINGS_KEY . '[log_level]">';
	foreach ($levels as $level => $label) {
		echo '<option value="' . esc_attr($level) . '" ' . selected($level, $settings['log_level'], false) . '>' . esc_html($label) . '</option>';
	}
	echo '</select>';
	echo '<p class="description">' . __('Higher log levels include all lower levels and generate more log entries.', 'enterprise-ajax-cache') . '</p>';
}

public function log_destination_callback() {
	$settings = $this->get_settings();

	$destinations = array(
		'wp_debug' => __('WordPress Debug Log', 'enterprise-ajax-cache'),
		'database' => __('Database', 'enterprise-ajax-cache'),
		'file' => __('Custom Log File', 'enterprise-ajax-cache'),
	);

	echo '<select name="' . AJAX_CACHE_SETTINGS_KEY . '[log_destination]" id="ajax_cache_log_destination">';
	foreach ($destinations as $dest => $label) {
		echo '<option value="' . esc_attr($dest) . '" ' . selected($dest, $settings['log_destination'], false) . '>' . esc_html($label) . '</option>';
	}
	echo '</select>';

	echo '<div id="log_file_path_container" ' . ($settings['log_destination'] == 'file' ? '' : 'style="display:none;"') . '>';
	echo '<p><input type="text" name="' . AJAX_CACHE_SETTINGS_KEY . '[log_file_path]" value="' . esc_attr(isset($settings['log_file_path']) ? $settings['log_file_path'] : WP_CONTENT_DIR . '/ajax-cache-logs.log') . '" class="regular-text" /></p>';
	echo '</div>';

	echo '<p class="description">' . __('Where log entries should be stored.', 'enterprise-ajax-cache') . '</p>';

	// Add JavaScript to show/hide the log file path field
	?>
	<script type="text/javascript">
        jQuery(document).ready(function($) {
            $('#ajax_cache_log_destination').on('change', function() {
                if ($(this).val() == 'file') {
                    $('#log_file_path_container').show();
                } else {
                    $('#log_file_path_container').hide();
                }
            });
        });
	</script>
	<?php
}

public function log_max_entries_callback() {
	$settings = $this->get_settings();
	echo '<input type="number" name="' . AJAX_CACHE_SETTINGS_KEY . '[log_max_entries]" value="' . esc_attr($settings['log_max_entries']) . '" min="10" step="10" class="small-text" />';
	echo '<p class="description">' . __('Maximum number of log entries to keep when using database logging.', 'enterprise-ajax-cache') . '</p>';
}

/**
 * Field callbacks - Cache Storage Section
 */
public function backend_callback() {
	$settings = $this->get_settings();

	// Check which backends are available
	$redis_available = function_exists('wp_redis') || class_exists('Redis');
	$memcached_available = class_exists('Memcached') || class_exists('Memcache');

	echo '<select name="' . AJAX_CACHE_SETTINGS_KEY . '[cache_backend]" id="ajax_cache_backend">';
	echo '<option value="transients" ' . selected('transients', $settings['cache_backend'], false) . '>' . __('WordPress Transients (Database)', 'enterprise-ajax-cache') . '</option>';

	if ($redis_available) {
		echo '<option value="redis" ' . selected('redis', $settings['cache_backend'], false) . '>' . __('Redis', 'enterprise-ajax-cache') . '</option>';
	} else {
		echo '<option value="redis" disabled>' . __('Redis (Not Available)', 'enterprise-ajax-cache') . '</option>';
	}

	if ($memcached_available) {
		echo '<option value="memcached" ' . selected('memcached', $settings['cache_backend'], false) . '>' . __('Memcached', 'enterprise-ajax-cache') . '</option>';
	} else {
		echo '<option value="memcached" disabled>' . __('Memcached (Not Available)', 'enterprise-ajax-cache') . '</option>';
	}

	echo '</select>';

	echo '<p class="description">' . __('Select where cached data should be stored. External caching systems provide better performance.', 'enterprise-ajax-cache') . '</p>';

	if (!$redis_available && !$memcached_available) {
		echo '<p class="description" style="color: #d63638;">' . __('Note: For better performance, consider installing Redis or Memcached.', 'enterprise-ajax-cache') . '</p>';
	}

	// Add JavaScript to show/hide the appropriate settings
	?>
	<script type="text/javascript">
        jQuery(document).ready(function($) {
            $('#ajax_cache_backend').on('change', function() {
                var backend = $(this).val();
                $('.backend-settings').hide();
                $('#' + backend + '_settings_container').show();
            });

            // Initial state
            $('.backend-settings').hide();
            $('#<?php echo esc_js($settings['cache_backend']); ?>_settings_container').show();
        });
	</script>
	<?php
}

public function redis_settings_callback() {
	$settings = $this->get_settings();
	$redis_settings = $settings['redis_settings'];

	echo '<div id="redis_settings_container" class="backend-settings">';
	echo '<table class="form-table" style="width: auto; margin-top: 0;">';
	echo '<tr>';
	echo '<th scope="row">' . __('Host', 'enterprise-ajax-cache') . '</th>';
	echo '<td><input type="text" name="' . AJAX_CACHE_SETTINGS_KEY . '[redis_settings][host]" value="' . esc_attr($redis_settings['host']) . '" class="regular-text" /></td>';
	echo '</tr>';

	echo '<tr>';
	echo '<th scope="row">' . __('Port', 'enterprise-ajax-cache') . '</th>';
	echo '<td><input type="number" name="' . AJAX_CACHE_SETTINGS_KEY . '[redis_settings][port]" value="' . esc_attr($redis_settings['port']) . '" class="small-text" /></td>';
	echo '</tr>';

	echo '<tr>';
	echo '<th scope="row">' . __('Password', 'enterprise-ajax-cache') . '</th>';
	echo '<td><input type="password" name="' . AJAX_CACHE_SETTINGS_KEY . '[redis_settings][auth]" value="' . esc_attr($redis_settings['auth']) . '" class="regular-text" /></td>';
	echo '</tr>';

	echo '<tr>';
	echo '<th scope="row">' . __('Database', 'enterprise-ajax-cache') . '</th>';
	echo '<td><input type="number" name="' . AJAX_CACHE_SETTINGS_KEY . '[redis_settings][database]" value="' . esc_attr($redis_settings['database']) . '" min="0" class="small-text" /></td>';
	echo '</tr>';
	echo '</table>';
	echo '</div>';
}

public function memcached_settings_callback() {
	$settings = $this->get_settings();
	$memcached_settings = $settings['memcached_settings'];

	echo '<div id="memcached_settings_container" class="backend-settings">';
	echo '<table class="form-table" style="width: auto; margin-top: 0;">';
	echo '<tr>';
	echo '<th scope="row">' . __('Host', 'enterprise-ajax-cache') . '</th>';
	echo '<td><input type="text" name="' . AJAX_CACHE_SETTINGS_KEY . '[memcached_settings][host]" value="' . esc_attr($memcached_settings['host']) . '" class="regular-text" /></td>';
	echo '</tr>';

	echo '<tr>';
	echo '<th scope="row">' . __('Port', 'enterprise-ajax-cache') . '</th>';
	echo '<td><input type="number" name="' . AJAX_CACHE_SETTINGS_KEY . '[memcached_settings][port]" value="' . esc_attr($memcached_settings['port']) . '" class="small-text" /></td>';
	echo '</tr>';
	echo '</table>';
	echo '</div>';
}

/**
 * Field callbacks - Cache Expiration Section
 */
public function default_expiration_callback() {
	$settings = $this->get_settings();

	echo '<input type="number" name="' . AJAX_CACHE_SETTINGS_KEY . '[default_expiration]" value="' . esc_attr($settings['default_expiration']) . '" min="60" step="60" class="small-text" />';
	echo '<p class="description">' . __('Default time in seconds until cached responses expire. Minimum 60 seconds.', 'enterprise-ajax-cache') . '</p>';

	$period_examples = array(
		60 => __('1 minute', 'enterprise-ajax-cache'),
		300 => __('5 minutes', 'enterprise-ajax-cache'),
		900 => __('15 minutes', 'enterprise-ajax-cache'),
		1800 => __('30 minutes', 'enterprise-ajax-cache'),
		3600 => __('1 hour', 'enterprise-ajax-cache'),
		7200 => __('2 hours', 'enterprise-ajax-cache'),
		14400 => __('4 hours', 'enterprise-ajax-cache'),
		43200 => __('12 hours', 'enterprise-ajax-cache'),
		86400 => __('1 day', 'enterprise-ajax-cache'),
		604800 => __('1 week', 'enterprise-ajax-cache'),
	);

	echo '<p class="description">' . __('Common values:', 'enterprise-ajax-cache') . ' ';
	$examples = array();
	foreach ($period_examples as $seconds => $label) {
		$examples[] = '<a href="#" class="expiration-preset" data-seconds="' . esc_attr($seconds) . '">' . esc_html($label) . '</a>';
	}
	echo implode(' | ', $examples);
	echo '</p>';

	// Add JavaScript to handle the preset links
	?>
	<script type="text/javascript">
        jQuery(document).ready(function($) {
            $('.expiration-preset').on('click', function(e) {
                e.preventDefault();
                $('input[name="<?php echo AJAX_CACHE_SETTINGS_KEY; ?>[default_expiration]"]').val($(this).data('seconds'));
            });
        });
	</script>
	<?php
}

public function per_action_expiration_callback() {
	$settings = $this->get_settings();
	$per_action_expiration = $settings['per_action_expiration'];
	$cacheable_actions = $settings['cacheable_actions'];

	if (empty($cacheable_actions)) {
		echo '<p class="description">' . __('No AJAX actions have been configured for caching. Add actions in the Cacheable Actions section below.', 'enterprise-ajax-cache') . '</p>';
		return;
	}

	echo '<div class="per-action-expiration-container">';
	echo '<table class="widefat striped" style="width: auto;">';
	echo '<thead>';
	echo '<tr>';
	echo '<th>' . __('AJAX Action', 'enterprise-ajax-cache') . '</th>';
	echo '<th>' . __('Expiration (seconds)', 'enterprise-ajax-cache') . '</th>';
	echo '</tr>';
	echo '</thead>';
	echo '<tbody>';

	foreach ($cacheable_actions as $action) {
		echo '<tr>';
		echo '<td>' . esc_html($action) . '</td>';
		echo '<td><input type="number" name="' . AJAX_CACHE_SETTINGS_KEY . '[per_action_expiration][' . esc_attr($action) . ']" value="' . esc_attr(isset($per_action_expiration[$action]) ? $per_action_expiration[$action] : $settings['default_expiration']) . '" min="60" step="60" class="small-text" /></td>';
		echo '</tr>';
	}

	echo '</tbody>';
	echo '</table>';
	echo '</div>';

	echo '<p class="description">' . __('Customize expiration time for specific AJAX actions. If not set, the default expiration time is used.', 'enterprise-ajax-cache') . '</p>';
}

/**
 * Field callbacks - Cacheable Actions Section
 */
public function cacheable_actions_callback() {
	$settings = $this->get_settings();
	$cacheable_actions = $settings['cacheable_actions'];

	echo '<div class="cacheable-actions-container">';

	// Current actions
	echo '<div class="current-actions">';
	echo '<h4>' . __('Currently Cached Actions', 'enterprise-ajax-cache') . '</h4>';

	if (empty($cacheable_actions)) {
		echo '<p class="description">' . __('No AJAX actions are currently configured for caching.', 'enterprise-ajax-cache') . '</p>';
	} else {
		echo '<table class="widefat striped" style="width: auto;">';
		echo '<thead>';
		echo '<tr>';
		echo '<th>' . __('AJAX Action', 'enterprise-ajax-cache') . '</th>';
		echo '<th>' . __('Remove', 'enterprise-ajax-cache') . '</th>';
		echo '</tr>';
		echo '</thead>';
		echo '<tbody>';

		foreach ($cacheable_actions as $index => $action) {
			echo '<tr>';
			echo '<td><input type="hidden" name="' . AJAX_CACHE_SETTINGS_KEY . '[cacheable_actions][]" value="' . esc_attr($action) . '" />' . esc_html($action) . '</td>';
			echo '<td><button type="button" class="button button-small remove-action" data-action="' . esc_attr($action) . '"><span class="dashicons dashicons-trash" style="margin-top: 3px;"></span></button></td>';
			echo '</tr>';
		}

		echo '</tbody>';
		echo '</table>';
	}
	echo '</div>';

	// Add new action
	echo '<div class="add-new-action" style="margin-top: 15px;">';
	echo '<h4>' . __('Add New Action', 'enterprise-ajax-cache') . '</h4>';

	// Get all registered AJAX actions
	$all_ajax_actions = $this->get_registered_ajax_actions();

	if (!empty($all_ajax_actions)) {
		echo '<select id="new_ajax_action" style="width: 300px;">';
		echo '<option value="">' . __('-- Select an AJAX action --', 'enterprise-ajax-cache') . '</option>';

		foreach ($all_ajax_actions as $action) {
			if (!in_array($action, $cacheable_actions)) {
				echo '<option value="' . esc_attr($action) . '">' . esc_html($action) . '</option>';
			}
		}

		echo '</select>';
		echo ' <button type="button" class="button button-secondary" id="add_ajax_action">' . __('Add', 'enterprise-ajax-cache') . '</button>';
		echo ' <span id="manual_action_toggle" class="button button-secondary">' . __('Enter Manually', 'enterprise-ajax-cache') . '</span>';
	}

	// Manual entry
	echo '<div id="manual_action_entry" style="margin-top: 10px; ' . (!empty($all_ajax_actions) ? 'display: none;' : '') . '">';
	echo '<input type="text" id="manual_ajax_action" placeholder="' . esc_attr__('Enter AJAX action name', 'enterprise-ajax-cache') . '" style="width: 300px;" />';
	echo ' <button type="button" class="button button-secondary" id="add_manual_action">' . __('Add', 'enterprise-ajax-cache') . '</button>';
	echo '</div>';

	echo '</div>';

	echo '</div>';

	// Add JavaScript to handle adding/removing actions
	?>
	<script type="text/javascript">
        jQuery(document).ready(function($) {
            // Add from dropdown
            $('#add_ajax_action').on('click', function() {
                var action = $('#new_ajax_action').val();
                if (action) {
                    addActionToTable(action);
                    $('#new_ajax_action option[value="' + action + '"]').remove();
                    $('#new_ajax_action').val('');
                }
            });

            // Add manual action
            $('#add_manual_action').on('click', function() {
                var action = $('#manual_ajax_action').val().trim();
                if (action) {
                    addActionToTable(action);
                    $('#manual_ajax_action').val('');
                }
            });

            // Toggle manual entry
            $('#manual_action_toggle').on('click', function() {
                $('#manual_action_entry').toggle();
            });

            // Remove action
            $(document).on('click', '.remove-action', function() {
                var action = $(this).data('action');
                $(this).closest('tr').remove();
                $('#new_ajax_action').append('<option value="' + action + '">' + action + '</option>');
            });

            function addActionToTable(action) {
                var tableBody = $('.current-actions table tbody');

                // If no table exists yet, create one
                if (tableBody.length === 0) {
                    $('.current-actions').html(
                        '<h4><?php echo esc_js(__('Currently Cached Actions', 'enterprise-ajax-cache')); ?></h4>' +
                        '<table class="widefat striped" style="width: auto;">' +
                        '<thead><tr>' +
                        '<th><?php echo esc_js(__('AJAX Action', 'enterprise-ajax-cache')); ?></th>' +
                        '<th><?php echo esc_js(__('Remove', 'enterprise-ajax-cache')); ?></th>' +
                        '</tr></thead>' +
                        '<tbody></tbody></table>'
                    );
                    tableBody = $('.current-actions table tbody');
                }

                tableBody.append(
                    '<tr>' +
                    '<td><input type="hidden" name="<?php echo AJAX_CACHE_SETTINGS_KEY; ?>[cacheable_actions][]" value="' + action + '" />' + action + '</td>' +
                    '<td><button type="button" class="button button-small remove-action" data-action="' + action + '"><span class="dashicons dashicons-trash" style="margin-top: 3px;"></span></button></td>' +
                    '</tr>'
                );
            }
        });
	</script>
	<?php
}

/**
 * Field callbacks - Cache Key Section
 */
public function key_params_callback() {
	$settings = $this->get_settings();
	$cache_key_params = $settings['cache_key_params'];
	$cacheable_actions = $settings['cacheable_actions'];

	if (empty($cacheable_actions)) {
		echo '<p class="description">' . __('No AJAX actions have been configured for caching. Add actions in the Cacheable Actions section first.', 'enterprise-ajax-cache') . '</p>';
		return;
	}

	echo '<div class="cache-key-params-container">';
	echo '<p class="description">' . __('Select which request parameters should be included in the cache key for each action.', 'enterprise-ajax-cache') . '</p>';
	echo '<p class="description">' . __('This allows different cache entries for different parameter values.', 'enterprise-ajax-cache') . '</p>';

	echo '<table class="widefat striped" style="width: auto; margin-top: 10px;">';
	echo '<thead>';
	echo '<tr>';
	echo '<th>' . __('AJAX Action', 'enterprise-ajax-cache') . '</th>';
	echo '<th>' . __('Request Parameters', 'enterprise-ajax-cache') . '</th>';
	echo '<th>' . __('Actions', 'enterprise-ajax-cache') . '</th>';
	echo '</tr>';
	echo '</thead>';
	echo '<tbody>';

	foreach ($cacheable_actions as $action) {
		echo '<tr data-action="' . esc_attr($action) . '">';
		echo '<td>' . esc_html($action) . '</td>';
		echo '<td class="param-list">';

		$action_params = isset($cache_key_params[$action]) ? $cache_key_params[$action] : array();

		if (empty($action_params)) {
			echo '<em>' . __('None - Cache key uses only the action name', 'enterprise-ajax-cache') . '</em>';
		} else {
			echo '<ul class="param-tag-list">';
			foreach ($action_params as $param) {
				echo '<li>';
				echo '<span class="param-tag">' . esc_html($param);
				echo '<input type="hidden" name="' . AJAX_CACHE_SETTINGS_KEY . '[cache_key_params][' . esc_attr($action) . '][]" value="' . esc_attr($param) . '" />';
				echo '<a href="#" class="remove-param" title="' . esc_attr__('Remove', 'enterprise-ajax-cache') . '">×</a>';
				echo '</span>';
				echo '</li>';
			}
			echo '</ul>';
		}

		echo '</td>';
		echo '<td>';
		echo '<div class="param-actions">';
		echo '<input type="text" class="new-param-input" placeholder="' . esc_attr__('Parameter name', 'enterprise-ajax-cache') . '" style="width: 150px;" />';
		echo '<button type="button" class="button button-small add-param">' . __('Add', 'enterprise-ajax-cache') . '</button>';
		echo '</div>';
		echo '</td>';
		echo '</tr>';
	}

	echo '</tbody>';
	echo '</table>';
	echo '</div>';

	// Add CSS for parameter tags
	?>
	<style>
        .param-tag-list {
            margin: 0;
            padding: 0;
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
        }
        .param-tag-list li {
            margin: 0;
            padding: 0;
            list-style: none;
        }
        .param-tag {
            display: inline-block;
            background: #f0f0f1;
            border-radius: 3px;
            padding: 3px 5px;
            margin-right: 5px;
            margin-bottom: 5px;
            border: 1px solid #c3c4c7;
        }
        .remove-param {
            margin-left: 5px;
            color: #d63638;
            text-decoration: none;
            font-weight: bold;
        }
        .param-actions {
            display: flex;
            align-items: center;
            gap: 5px;
        }
	</style>

	<!-- Add JavaScript to handle adding/removing parameters -->
	<script type="text/javascript">
        jQuery(document).ready(function($) {
            // Add parameter
            $('.add-param').on('click', function() {
                var row = $(this).closest('tr');
                var action = row.data('action');
                var paramInput = row.find('.new-param-input');
                var param = paramInput.val().trim();

                if (param) {
                    var paramList = row.find('.param-list');
                    var existingParams = paramList.find('input[type="hidden"]').map(function() {
                        return $(this).val();
                    }).get();

                    // Check if parameter already exists
                    if ($.inArray(param, existingParams) !== -1) {
                        alert('<?php echo esc_js(__('This parameter is already in the list.', 'enterprise-ajax-cache')); ?>');
                        return;
                    }

                    // Remove "None" message if it exists
                    paramList.find('em').remove();

                    // Create or get the parameter list
                    var paramTagList = paramList.find('.param-tag-list');
                    if (paramTagList.length === 0) {
                        paramList.html('<ul class="param-tag-list"></ul>');
                        paramTagList = paramList.find('.param-tag-list');
                    }

                    // Add the new parameter
                    paramTagList.append(
                        '<li>' +
                        '<span class="param-tag">' + param +
                        '<input type="hidden" name="<?php echo AJAX_CACHE_SETTINGS_KEY; ?>[cache_key_params][' + action + '][]" value="' + param + '" />' +
                        '<a href="#" class="remove-param" title="<?php echo esc_js(__('Remove', 'enterprise-ajax-cache')); ?>">×</a>' +
                        '</span>' +
                        '</li>'
                    );

                    // Clear the input
                    paramInput.val('');
                }
            });

            // Enter key should trigger add button
            $('.new-param-input').on('keypress', function(e) {
                if (e.which === 13) { // Enter key
                    e.preventDefault();
                    $(this).closest('tr').find('.add-param').click();
                }
            });

            // Remove parameter
            $(document).on('click', '.remove-param', function(e) {
                e.preventDefault();
                var listItem = $(this).closest('li');
                var paramList = listItem.closest('.param-list');

                listItem.remove();

                // If no parameters left, show "None" message
                if (paramList.find('li').length === 0) {
                    paramList.html('<em><?php echo esc_js(__('None - Cache key uses only the action name', 'enterprise-ajax-cache')); ?></em>');
                }
            });
        });
	</script>
	<?php
}

public function key_factors_callback() {
	$settings = $this->get_settings();
	$factors = $settings['cache_key_factors'];

	echo '<p class="description">' . __('Select which user-specific factors should be included in all cache keys.', 'enterprise-ajax-cache') . '</p>';

	echo '<p>';
	echo '<label><input type="checkbox" name="' . AJAX_CACHE_SETTINGS_KEY . '[cache_key_factors][user_id]" value="1" ' . checked(1, $factors['user_id'], false) . '/> ';
	echo __('User ID', 'enterprise-ajax-cache') . '</label>';
	echo '<p class="description" style="margin-left: 25px;">' . __('Each user will have their own separate cache entries.', 'enterprise-ajax-cache') . '</p>';
	echo '</p>';

	echo '<p>';
	echo '<label><input type="checkbox" name="' . AJAX_CACHE_SETTINGS_KEY . '[cache_key_factors][user_roles]" value="1" ' . checked(1, $factors['user_roles'], false) . '/> ';
	echo __('User Roles', 'enterprise-ajax-cache') . '</label>';
	echo '<p class="description" style="margin-left: 25px;">' . __('Users with different roles will have separate cache entries.', 'enterprise-ajax-cache') . '</p>';
	echo '</p>';
}

public function key_cookies_callback() {
$settings = $this->get_settings();
$cache_key_cookies = $settings['cache_key_cookies'];
$cacheable_actions = $settings['cacheable_actions'];

if (empty($cacheable_actions)) {
	echo '<p class="description">' . __('No AJAX actions have been configured for caching. Add actions in the Cacheable Actions section first.', 'enterprise-ajax-cache') . '</p>';
	return;
}

echo '<div class="cache-key-cookies-container">';
echo '<p class="description">' . __('Select which cookies should be included in the cache key for each action.', 'enterprise-ajax-cache') . '</p>';
echo '<p class="description">' . __('This is useful for session-specific or user preference cookies.', 'enterprise-ajax-cache') . '</p>';

echo '<table class="widefat striped" style="width: auto; margin-top: 10px;">';
echo '<thead>';
echo '<tr>';
echo '<th>' . __('AJAX Action', 'enterprise-ajax-cache') . '</th>';
echo '<th>' . __('Cookies', 'enterprise-ajax-cache') . '</th>';
echo '<th>' . __('Actions', 'enterprise-ajax-cache') . '</th>';
echo '</tr>';
echo '</thead>';
echo '<tbody>';

foreach ($cacheable_actions as $action) {
	echo '<tr data-action="' . esc_attr($action) . '">';
	echo '<td>' . esc_html($action) . '</td>';
	echo '<td class="cookie-list">';

	$action_cookies = isset($cache_key_cookies[$action]) ? $cache_key_cookies[$action] : array();

	if (empty($action_cookies)) {
		echo '<em>' . __('None', 'enterprise-ajax-cache') . '</em>';
	} else {
		echo '<ul class="cookie-tag-list">';
		foreach ($action_cookies as $cookie) {
			echo '<li>';
			echo '<span class="cookie-tag">' . esc_html($cookie);
			echo '<input type="hidden" name="' . AJAX_CACHE_SETTINGS_KEY . '[cache_key_cookies][' . esc_attr($action) . '][]" value="' . esc_attr($cookie) . '" />';
			echo '<a href="#" class="remove-cookie" title="' . esc_attr__('Remove', 'enterprise-ajax-cache') . '">×</a>';
			echo '</span>';
			echo '</li>';
		}
		echo '</ul>';
	}

	echo '</td>';
	echo '<td>';
	echo '<div class="cookie-actions">';
	echo '<input type="text" class="new-cookie-input" placeholder="' . esc_attr__('Cookie name', 'enterprise-ajax-cache') . '" style="width: 150px;" />';
	echo '<button type="button" class="button button-small add-cookie">' . __('Add', 'enterprise-ajax-cache') . '</button>';
	echo '</div>';

	// Common cookies dropdown
	$common_cookies = array(
		'wordpress_logged_in' => __('WordPress Login Cookie', 'enterprise-ajax-cache'),
		'woocommerce_cart_hash' => __('WooCommerce Cart Hash', 'enterprise-ajax-cache'),
		'woocommerce_items_in_cart' => __('WooCommerce Items in Cart', 'enterprise-ajax-cache'),
		'wp_woocommerce_session' => __('WooCommerce Session', 'enterprise-ajax-cache'),
		'PHPSESSID' => __('PHP Session ID', 'enterprise-ajax-cache'),
	);

	if (!empty($common_cookies)) {
		echo '<div style="margin-top: 5px;">';
		echo '<select class="common-cookies" style="width: 150px;">';
		echo '<option value="">' . __('-- Common cookies --', 'enterprise-ajax-cache') . '</option>';

		foreach ($common_cookies as $cookie => $label) {
			echo '<option value="' . esc_attr($cookie) . '">' . esc_html($label) . '</option>';
		}

		echo '</select>';
		echo '<button type="button" class="button button-small add-common-cookie" style="margin-left: 5px;">' . __('Add', 'enterprise-ajax-cache') . '</button>';
		echo '</div>';
	}

	echo '</td>';
	echo '</tr>';
}

echo '</tbody>';
echo '</table>';
echo '</div>';

// Add CSS for cookie tags
?>
<style>
    .cookie-tag-list {
        margin: 0;
        padding: 0;
        display: flex;
        flex-wrap: wrap;
        gap: 5px;
    }
    .cookie-tag-list li {
        margin: 0;
        padding: 0;
        list-style: none;
    }
    .cookie-tag {
        display: inline-block;
        background: #f0f0f1;
        border-radius: 3px;
        padding: 3px 5px;
        margin-right: 5px;
        margin-bottom: 5px;
        border: 1px solid #c3c4c7;
    }
    .remove-cookie {
        margin-left: 5px;
        color: #d63638;
        text-decoration: none;
        font-weight: bold;
    }
    .cookie-actions {
        display: flex;
        align-items: center;
        gap: 5px;
    }
</style>

	<!-- Add JavaScript to handle adding/removing cookies -->
	<script type="text/javascript">
        jQuery(document).ready(function($) {
            // Add cookie
            $('.add-cookie').on('click', function() {
                var row = $(this).closest('tr');
                var action = row.data('action');
                var cookieInput = row.find('.new-cookie-input');
                var cookie = cookieInput.val().trim();

                if (cookie) {
                    addCookieToList(row, action, cookie);
                    cookieInput.val('');
                }
            });

            // Add common cookie
            $('.add-common-cookie').on('click', function() {
                var row = $(this).closest('tr');
                var action = row.data('action');
                var cookieSelect = row.find('.common-cookies');
                var cookie = cookieSelect.val();

                if (cookie) {
                    addCookieToList(row, action, cookie);
                    cookieSelect.val('');
                }
            });

            // Enter key should trigger add button
            $('.new-cookie-input').on('keypress', function(e) {
                if (e.which === 13) { // Enter key
                    e.preventDefault();
                    $(this).closest('tr').find('.add-cookie').click();
                }
            });

            // Remove cookie
            $(document).on('click', '.remove-cookie', function(e) {
                e.preventDefault();
                var listItem = $(this).closest('li');
                var cookieList = listItem.closest('.cookie-list');

                listItem.remove();

                // If no cookies left, show "None" message
                if (cookieList.find('li').length === 0) {
                    cookieList.html('<em><?php echo esc_js(__('None', 'enterprise-ajax-cache')); ?></em>');
                }
            });

            // Function to add cookie to the list
            function addCookieToList(row, action, cookie) {
                var cookieList = row.find('.cookie-list');
                var existingCookies = cookieList.find('input[type="hidden"]').map(function() {
                    return $(this).val();
                }).get();

                // Check if cookie already exists
                if ($.inArray(cookie, existingCookies) !== -1) {
                    alert('<?php echo esc_js(__('This cookie is already in the list.', 'enterprise-ajax-cache')); ?>');
                    return;
                }

                // Remove "None" message if it exists
                cookieList.find('em').remove();

                // Create or get the cookie list
                var cookieTagList = cookieList.find('.cookie-tag-list');
                if (cookieTagList.length === 0) {
                    cookieList.html('<ul class="cookie-tag-list"></ul>');
                    cookieTagList = cookieList.find('.cookie-tag-list');
                }

                // Add the new cookie
                cookieTagList.append(
                    '<li>' +
                    '<span class="cookie-tag">' + cookie +
                    '<input type="hidden" name="<?php echo AJAX_CACHE_SETTINGS_KEY; ?>[cache_key_cookies][' + action + '][]" value="' + cookie + '" />' +
                    '<a href="#" class="remove-cookie" title="<?php echo esc_js(__('Remove', 'enterprise-ajax-cache')); ?>">×</a>' +
                    '</span>' +
                    '</li>'
                );
            }
        });
	</script>
	<?php
}
	/**
	 * Field callbacks - Cache Invalidation Section
	 */
	public function watched_post_types_callback() {
		$settings = $this->get_settings();
		$watched_post_types = $settings['watched_post_types'];

		// Get all registered post types
		$post_types = get_post_types(array('public' => true), 'objects');

		echo '<div class="watched-post-types-container">';
		echo '<p class="description">' . __('Select which post types should trigger cache invalidation when updated:', 'enterprise-ajax-cache') . '</p>';

		foreach ($post_types as $post_type) {
			$checked = in_array($post_type->name, $watched_post_types);

			echo '<p>';
			echo '<label><input type="checkbox" name="' . AJAX_CACHE_SETTINGS_KEY . '[watched_post_types][]" value="' . esc_attr($post_type->name) . '" ' . checked(true, $checked, false) . '/> ';
			echo esc_html($post_type->label) . ' (' . esc_html($post_type->name) . ')</label>';
			echo '</p>';
		}

		echo '</div>';
	}

	public function invalidation_rules_callback() {
		$settings = $this->get_settings();
		$invalidation_rules = $settings['invalidation_rules'];
		$watched_post_types = $settings['watched_post_types'];
		$cacheable_actions = $settings['cacheable_actions'];

		if (empty($watched_post_types)) {
			echo '<p class="description">' . __('No post types are being watched for updates. Select post types in the option above.', 'enterprise-ajax-cache') . '</p>';
			return;
		}

		if (empty($cacheable_actions)) {
			echo '<p class="description">' . __('No AJAX actions have been configured for caching. Add actions in the Cacheable Actions section first.', 'enterprise-ajax-cache') . '</p>';
			return;
		}

		echo '<div class="invalidation-rules-container">';
		echo '<p class="description">' . __('Configure which AJAX cache actions should be invalidated when posts of specific types are updated:', 'enterprise-ajax-cache') . '</p>';

		echo '<table class="widefat striped" style="width: auto; margin-top: 10px;">';
		echo '<thead>';
		echo '<tr>';
		echo '<th>' . __('Post Type', 'enterprise-ajax-cache') . '</th>';
		echo '<th>' . __('Actions to Invalidate', 'enterprise-ajax-cache') . '</th>';
		echo '</tr>';
		echo '</thead>';
		echo '<tbody>';

		foreach ($watched_post_types as $post_type) {
			$post_type_obj = get_post_type_object($post_type);

			echo '<tr>';
			echo '<td>' . esc_html($post_type_obj ? $post_type_obj->label : $post_type) . '</td>';
			echo '<td>';

			foreach ($cacheable_actions as $action) {
				$checked = isset($invalidation_rules[$post_type]) && in_array($action, $invalidation_rules[$post_type]);

				echo '<p>';
				echo '<label><input type="checkbox" name="' . AJAX_CACHE_SETTINGS_KEY . '[invalidation_rules][' . esc_attr($post_type) . '][]" value="' . esc_attr($action) . '" ' . checked(true, $checked, false) . '/> ';
				echo esc_html($action) . '</label>';
				echo '</p>';
			}

			echo '</td>';
			echo '</tr>';
		}

		echo '</tbody>';
		echo '</table>';
		echo '</div>';
	}

	public function auto_purge_schedule_callback() {
		$settings = $this->get_settings();
		$schedule = $settings['auto_purge_schedule'];

		$schedules = array(
			'never' => __('Never (Manual purge only)', 'enterprise-ajax-cache'),
			'hourly' => __('Hourly', 'enterprise-ajax-cache'),
			'twicedaily' => __('Twice Daily', 'enterprise-ajax-cache'),
			'daily' => __('Daily', 'enterprise-ajax-cache'),
			'weekly' => __('Weekly', 'enterprise-ajax-cache'),
		);

		echo '<select name="' . AJAX_CACHE_SETTINGS_KEY . '[auto_purge_schedule]">';
		foreach ($schedules as $key => $label) {
			echo '<option value="' . esc_attr($key) . '" ' . selected($key, $schedule, false) . '>' . esc_html($label) . '</option>';
		}
		echo '</select>';

		echo '<p class="description">' . __('Automatically purge all caches on a regular schedule.', 'enterprise-ajax-cache') . '</p>';
	}

	/**
	 * Utility function to get all registered AJAX actions
	 *
	 * @return array List of registered AJAX actions
	 */
	public function get_registered_ajax_actions() {
		global $wp_filter;
		$ajax_actions = array();

		// Look for WordPress AJAX handlers
		$ajax_hooks = array('wp_ajax_', 'wp_ajax_nopriv_');

		foreach ($ajax_hooks as $ajax_hook) {
			$len = strlen($ajax_hook);

			foreach ($wp_filter as $filter_name => $filter_obj) {
				if (strpos($filter_name, $ajax_hook) === 0) {
					$action = substr($filter_name, $len);
					$ajax_actions[] = $action;
				}
			}
		}

		// Some commonly used AJAX actions in popular plugins
		$common_actions = array(
			// WooCommerce
			'woocommerce_get_refreshed_fragments',
			'woocommerce_apply_coupon',
			'woocommerce_remove_coupon',
			'woocommerce_update_shipping_method',
			'woocommerce_update_order_review',
			'woocommerce_checkout',
			'woocommerce_get_cart_totals',
			'woocommerce_add_to_cart',
			'woocommerce_remove_from_cart',
			'woocommerce_set_cart_item_quantity',

			// Gravity Forms
			'rg_save_form',
			'rg_update_lead_property',
			'rg_update_form_active',

			// Contact Form 7
			'wpcf7_submit',

			// Elementor
			'elementor_ajax',

			// Yoast SEO
			'wpseo_get_focus_keyword_assessment',
			'wpseo_set_ignore',
			'wpseo_update_page_status',

			// WordPress core
			'heartbeat',
			'fetch-list',
			'wp-compression-test',
			'wp-link-ajax',
			'menu-quick-search',
		);

		$ajax_actions = array_merge($ajax_actions, $common_actions);
		$ajax_actions = array_unique($ajax_actions);
		sort($ajax_actions);

		return $ajax_actions;
	}

	/**
	 * Export settings handler
	 */
	public function export_settings() {
		if (!current_user_can('manage_options') || !isset($_POST['export_settings']) || !check_admin_referer('ajax_cache_export_settings')) {
			return;
		}

		$settings = get_option(AJAX_CACHE_SETTINGS_KEY, array());
		$settings_json = json_encode($settings, JSON_PRETTY_PRINT);

		header('Content-Type: application/json');
		header('Content-Disposition: attachment; filename=ajax-cache-settings-' . date('Y-m-d') . '.json');
		header('Cache-Control: must-revalidate');
		header('Pragma: public');
		header('Content-Length: ' . strlen($settings_json));

		echo $settings_json;
		exit;
	}

	/**
	 * Import settings handler
	 */
	public function import_settings() {
		if (!current_user_can('manage_options') || !isset($_POST['import_settings']) || !check_admin_referer('ajax_cache_import_settings')) {
			return;
		}

		$redirect_url = admin_url('tools.php?page=enterprise-ajax-cache&tab=tools');

		if (!isset($_FILES['settings_file']) || $_FILES['settings_file']['error'] > 0) {
			$error_message = isset($_FILES['settings_file']) ? $_FILES['settings_file']['error'] : __('No file uploaded', 'enterprise-ajax-cache');
			wp_redirect(add_query_arg('import_error', urlencode($error_message), $redirect_url));
			exit;
		}

		$file = $_FILES['settings_file'];
		$file_content = file_get_contents($file['tmp_name']);

		if (!$file_content) {
			wp_redirect(add_query_arg('import_error', urlencode(__('Could not read file', 'enterprise-ajax-cache')), $redirect_url));
			exit;
		}

		$settings = json_decode($file_content, true);

		if (json_last_error() !== JSON_ERROR_NONE) {
			wp_redirect(add_query_arg('import_error', urlencode(__('Invalid JSON file', 'enterprise-ajax-cache')), $redirect_url));
			exit;
		}

		// Sanitize and save settings
		$sanitized_settings = $this->sanitize_settings($settings);
		update_option(AJAX_CACHE_SETTINGS_KEY, $sanitized_settings);

		wp_redirect(add_query_arg('import_success', '1', $redirect_url));
		exit;
	}

	/**
	 * Reset statistics
	 */
	public function reset_statistics() {
		if (isset($_GET['reset_stats']) && current_user_can('manage_options') && check_admin_referer('reset_ajax_cache_stats')) {
			update_option('ajax_cache_stats', array(
				'hits' => 0,
				'misses' => 0,
				'sets' => 0,
				'purges' => 0,
				'last_purge' => 0
			));

			wp_redirect(add_query_arg('tab', 'statistics', admin_url('tools.php?page=enterprise-ajax-cache')));
			exit;
		}
	}

	/**
	 * Handle import/export messages
	 */
	public function admin_notices() {
		if (isset($_GET['page']) && $_GET['page'] === 'enterprise-ajax-cache' && isset($_GET['tab']) && $_GET['tab'] === 'tools') {
			if (isset($_GET['import_error'])) {
				$error = sanitize_text_field($_GET['import_error']);
				echo '<div class="notice notice-error"><p>' . sprintf(__('Import failed: %s', 'enterprise-ajax-cache'), $error) . '</p></div>';
			}

			if (isset($_GET['import_success'])) {
				echo '<div class="notice notice-success"><p>' . __('Settings imported successfully.', 'enterprise-ajax-cache') . '</p></div>';
			}
		}
	}

	/**
	 * Render the settings page
	 */
	public function render_settings_page() {
		// Check user capabilities
		if (!current_user_can('manage_options')) {
			return;
		}

		// Handle form submissions
		if (isset($_POST['clear_all_caches']) && check_admin_referer('ajax_cache_clear_all')) {
			$count = $this->plugin->purge_all_caches();
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
				$count = $this->plugin->purge_cache_by_action($action);
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

		// Get cache statistics
		$stats = get_option('ajax_cache_stats', array(
			'hits' => 0,
			'misses' => 0,
			'sets' => 0,
			'purges' => 0,
			'last_purge' => 0
		));

		// Check system compatibility
		$compatibility = $this->plugin->check_compatibility();

		// Get current tab
		$current_tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'general';

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

			<h2 class="nav-tab-wrapper">
				<a href="?page=enterprise-ajax-cache&tab=general" class="nav-tab <?php echo $current_tab === 'general' ? 'nav-tab-active' : ''; ?>"><?php _e('General', 'enterprise-ajax-cache'); ?></a>
				<a href="?page=enterprise-ajax-cache&tab=cache-actions" class="nav-tab <?php echo $current_tab === 'cache-actions' ? 'nav-tab-active' : ''; ?>"><?php _e('Cache Actions', 'enterprise-ajax-cache'); ?></a>
				<a href="?page=enterprise-ajax-cache&tab=cache-keys" class="nav-tab <?php echo $current_tab === 'cache-keys' ? 'nav-tab-active' : ''; ?>"><?php _e('Cache Keys', 'enterprise-ajax-cache'); ?></a>
				<a href="?page=enterprise-ajax-cache&tab=invalidation" class="nav-tab <?php echo $current_tab === 'invalidation' ? 'nav-tab-active' : ''; ?>"><?php _e('Invalidation', 'enterprise-ajax-cache'); ?></a>
				<a href="?page=enterprise-ajax-cache&tab=statistics" class="nav-tab <?php echo $current_tab === 'statistics' ? 'nav-tab-active' : ''; ?>"><?php _e('Statistics', 'enterprise-ajax-cache'); ?></a>
				<a href="?page=enterprise-ajax-cache&tab=logs" class="nav-tab <?php echo $current_tab === 'logs' ? 'nav-tab-active' : ''; ?>"><?php _e('Logs', 'enterprise-ajax-cache'); ?></a>
				<a href="?page=enterprise-ajax-cache&tab=tools" class="nav-tab <?php echo $current_tab === 'tools' ? 'nav-tab-active' : ''; ?>"><?php _e('Tools', 'enterprise-ajax-cache'); ?></a>
			</h2>

			<div class="tab-content">
				<?php if ($current_tab === 'general'): ?>
					<form method="post" action="options.php">
						<?php
						settings_fields('ajax_cache_settings');
						?>

						<h2><?php _e('General Settings', 'enterprise-ajax-cache'); ?></h2>
						<?php do_settings_sections('ajax_cache_settings'); ?>

						<?php submit_button(); ?>
					</form>

				<?php elseif ($current_tab === 'cache-actions'): ?>
					<form method="post" action="options.php">
						<?php
						settings_fields('ajax_cache_settings');
						?>

						<h2><?php _e('Cacheable Actions', 'enterprise-ajax-cache'); ?></h2>
						<p><?php _e('Configure which AJAX actions should be cached and their expiration times.', 'enterprise-ajax-cache'); ?></p>

						<?php
						do_settings_section('ajax_cache_actions_section');
						do_settings_section('ajax_cache_expiration_section');
						?>

						<?php submit_button(); ?>
					</form>

				<?php elseif ($current_tab === 'cache-keys'): ?>
					<form method="post" action="options.php">
						<?php
						settings_fields('ajax_cache_settings');
						?>

						<h2><?php _e('Cache Key Configuration', 'enterprise-ajax-cache'); ?></h2>
						<p><?php _e('Configure how cache keys are generated for each AJAX action.', 'enterprise-ajax-cache'); ?></p>

						<?php
						do_settings_section('ajax_cache_key_section');
						?>

						<?php submit_button(); ?>
					</form>

				<?php elseif ($current_tab === 'invalidation'): ?>
					<form method="post" action="options.php">
						<?php
						settings_fields('ajax_cache_settings');
						?>

						<h2><?php _e('Cache Invalidation', 'enterprise-ajax-cache'); ?></h2>
						<p><?php _e('Configure when caches should be automatically invalidated.', 'enterprise-ajax-cache'); ?></p>

						<?php
						do_settings_section('ajax_cache_invalidation_section');
						?>

						<?php submit_button(); ?>
					</form>

				<?php elseif ($current_tab === 'statistics'): ?>
					<h2><?php _e('Cache Statistics', 'enterprise-ajax-cache'); ?></h2>

					<div class="card">
						<h3><?php _e('Performance Metrics', 'enterprise-ajax-cache'); ?></h3>

						<table class="widefat striped" style="width: auto;">
							<tbody>
							<tr>
								<th><?php _e('Cache Hits', 'enterprise-ajax-cache'); ?></th>
								<td><?php echo esc_html(number_format($stats['hits'])); ?></td>
							</tr>
							<tr>
								<th><?php _e('Cache Misses', 'enterprise-ajax-cache'); ?></th>
								<td><?php echo esc_html(number_format($stats['misses'])); ?></td>
							</tr>
							<tr>
								<th><?php _e('Total Requests', 'enterprise-ajax-cache'); ?></th>
								<td><?php echo esc_html(number_format($stats['hits'] + $stats['misses'])); ?></td>
							</tr>
							<tr>
								<th><?php _e('Cache Hit Ratio', 'enterprise-ajax-cache'); ?></th>
								<td>
									<?php
									if (($stats['hits'] + $stats['misses']) > 0) {
										$hit_ratio = ($stats['hits'] / ($stats['hits'] + $stats['misses'])) * 100;
										echo esc_html(round($hit_ratio, 2)) . '%';
									} else {
										echo '0%';
									}
									?>
								</td>
							</tr>
							<tr>
								<th><?php _e('Cache Sets (New Entries)', 'enterprise-ajax-cache'); ?></th>
								<td><?php echo esc_html(number_format($stats['sets'])); ?></td>
							</tr>
							<tr>
								<th><?php _e('Cache Purges', 'enterprise-ajax-cache'); ?></th>
								<td><?php echo esc_html(number_format($stats['purges'])); ?></td>
							</tr>
							<?php if ($stats['last_purge'] > 0): ?>
								<tr>
									<th><?php _e('Last Purge', 'enterprise-ajax-cache'); ?></th>
									<td>
										<?php
										echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $stats['last_purge']));
										$time_ago = human_time_diff($stats['last_purge'], time());
										echo ' (' . sprintf(__('%s ago', 'enterprise-ajax-cache'), $time_ago) . ')';
										?>
									</td>
								</tr>
							<?php endif; ?>
							</tbody>
						</table>

						<p>
							<a href="<?php echo esc_url(wp_nonce_url(add_query_arg('reset_stats', 'true'), 'reset_ajax_cache_stats')); ?>" class="button" onclick="return confirm('<?php esc_attr_e('Are you sure you want to reset statistics? This action cannot be undone.', 'enterprise-ajax-cache'); ?>');">
								<?php _e('Reset Statistics', 'enterprise-ajax-cache'); ?>
							</a>
						</p>
					</div>

					<div class="card">
						<h3><?php _e('Cache Backend Status', 'enterprise-ajax-cache'); ?></h3>
						<?php
						$settings = $this->get_settings();
						$backend = $settings['cache_backend'];

						echo '<p><strong>' . __('Active Cache Backend:', 'enterprise-ajax-cache') . '</strong> ';

						switch ($backend) {
							case 'redis':
								echo __('Redis', 'enterprise-ajax-cache');
								echo '</p>';

								// Check Redis connection
								if (function_exists('wp_redis') && defined('WP_REDIS_ENABLED') && WP_REDIS_ENABLED) {
									echo '<p class="notice notice-success">' . __('Redis is properly configured and connected.', 'enterprise-ajax-cache') . '</p>';
								} else {
									echo '<p class="notice notice-error">' . __('Redis is selected but not properly configured or connected.', 'enterprise-ajax-cache') . '</p>';
								}

								echo '<p><strong>' . __('Redis Settings:', 'enterprise-ajax-cache') . '</strong></p>';
								echo '<ul>';
								echo '<li>' . __('Host:', 'enterprise-ajax-cache') . ' ' . esc_html($settings['redis_settings']['host']) . '</li>';
								echo '<li>' . __('Port:', 'enterprise-ajax-cache') . ' ' . esc_html($settings['redis_settings']['port']) . '</li>';
								echo '<li>' . __('Database:', 'enterprise-ajax-cache') . ' ' . esc_html($settings['redis_settings']['database']) . '</li>';
								echo '</ul>';
								break;

							case 'memcached':
								echo __('Memcached', 'enterprise-ajax-cache');
								echo '</p>';

								// Check Memcached connection
								if (class_exists('WP_Object_Cache') && isset($GLOBALS['wp_object_cache']) &&
								    method_exists($GLOBALS['wp_object_cache'], 'get_with_fallback') &&
								    $GLOBALS['wp_object_cache']->is_memcache) {
									echo '<p class="notice notice-success">' . __('Memcached is properly configured and connected.', 'enterprise-ajax-cache') . '</p>';
								} else {
									echo '<p class="notice notice-error">' . __('Memcached is selected but not properly configured or connected.', 'enterprise-ajax-cache') . '</p>';
								}

								echo '<p><strong>' . __('Memcached Settings:', 'enterprise-ajax-cache') . '</strong></p>';
								echo '<ul>';
								echo '<li>' . __('Host:', 'enterprise-ajax-cache') . ' ' . esc_html($settings['memcached_settings']['host']) . '</li>';
								echo '<li>' . __('Port:', 'enterprise-ajax-cache') . ' ' . esc_html($settings['memcached_settings']['port']) . '</li>';
								echo '</ul>';
								break;

							case 'transients':
							default:
								echo __('WordPress Transients (Database)', 'enterprise-ajax-cache');
								echo '</p>';

								global $wpdb;
								$transients_count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '%_transient_ajax_cache_%'");

								echo '<p>' . sprintf(__('Current transient count: %d', 'enterprise-ajax-cache'), $transients_count) . '</p>';

								// Check if external object cache is available
								if (wp_using_ext_object_cache()) {
									echo '<p class="notice notice-info">' . __('WordPress is using an external object cache, which may improve transient performance.', 'enterprise-ajax-cache') . '</p>';
								} else {
									echo '<p class="notice notice-warning">' . __('WordPress is using database transients. For better performance, consider using Redis or Memcached.', 'enterprise-ajax-cache') . '</p>';
								}
								break;
						}
						?>
					</div>

				<?php elseif ($current_tab === 'logs'): ?>
					<h2><?php _e('Log Viewer', 'enterprise-ajax-cache'); ?></h2>
					<?php
					$settings = $this->get_settings();
					$log_destination = $settings['log_destination'];

					if ($log_destination === 'database') {
						$logs = get_option('ajax_cache_logs', array());

						if (empty($logs)) {
							echo '<p>' . __('No logs available.', 'enterprise-ajax-cache') . '</p>';
						} else {
							echo '<table class="widefat striped">';
							echo '<thead>';
							echo '<tr>';
							echo '<th>' . __('Time', 'enterprise-ajax-cache') . '</th>';
							echo '<th>' . __('Level', 'enterprise-ajax-cache') . '</th>';
							echo '<th>' . __('Message', 'enterprise-ajax-cache') . '</th>';
							echo '<th>' . __('Context', 'enterprise-ajax-cache') . '</th>';
							echo '</tr>';
							echo '</thead>';
							echo '<tbody>';

							foreach ($logs as $log) {
								echo '<tr>';
								echo '<td>' . esc_html($log['timestamp']) . '</td>';
								echo '<td>' . esc_html($this->get_level_name($log['level'])) . '</td>';
								echo '<td>' . esc_html($log['message']) . '</td>';
								echo '<td>' . (!empty($log['context']) ? '<pre>' . esc_html(json_encode($log['context'], JSON_PRETTY_PRINT)) . '</pre>' : '') . '</td>';
								echo '</tr>';
							}

							echo '</tbody>';
							echo '</table>';

							echo '<p>';
							echo '<a href="' . esc_url(wp_nonce_url(add_query_arg('clear_logs', 'true'), 'clear_ajax_cache_logs')) . '" class="button" onclick="return confirm(\'' . esc_attr__('Are you sure you want to clear all logs? This action cannot be undone.', 'enterprise-ajax-cache') . '\');">';
							echo __('Clear Logs', 'enterprise-ajax-cache');
							echo '</a>';
							echo '</p>';
						}
					} elseif ($log_destination === 'file') {
						$log_file = isset($settings['log_file_path']) ? $settings['log_file_path'] : WP_CONTENT_DIR . '/ajax-cache-logs.log';

						if (file_exists($log_file) && is_readable($log_file)) {
							$logs = file_get_contents($log_file);
							if (!empty($logs)) {
								echo '<div style="background: #f0f0f1; padding: 10px; border: 1px solid #c3c4c7; max-height: 500px; overflow: auto;">';
								echo '<pre>' . esc_html($logs) . '</pre>';
								echo '</div>';

								echo '<p>';
								echo '<a href="' . esc_url(wp_nonce_url(add_query_arg('clear_log_file', 'true'), 'clear_ajax_cache_log_file')) . '" class="button" onclick="return confirm(\'' . esc_attr__('Are you sure you want to clear the log file? This action cannot be undone.', 'enterprise-ajax-cache') . '\');">';
								echo __('Clear Log File', 'enterprise-ajax-cache');
								echo '</a>';
								echo '</p>';
							} else {
								echo '<p>' . __('Log file is empty.', 'enterprise-ajax-cache') . '</p>';
							}
						} else {
							echo '<p>' . __('Log file does not exist or is not readable.', 'enterprise-ajax-cache') . '</p>';
						}
					} else {
						echo '<p>' . __('Logs are being written to the WordPress debug log.', 'enterprise-ajax-cache') . '</p>';

						if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
							echo '<p>' . __('WordPress debug logging is enabled.', 'enterprise-ajax-cache') . '</p>';
						} else {
							echo '<p class="notice notice-warning">' . __('WordPress debug logging is not enabled. Add <code>define(\'WP_DEBUG_LOG\', true);</code> to your wp-config.php file to enable it.', 'enterprise-ajax-cache') . '</p>';
						}
					}
					?>

				<?php elseif ($current_tab === 'tools'): ?>
					<h2><?php _e('Cache Management Tools', 'enterprise-ajax-cache'); ?></h2>

					<div class="card">
						<h3><?php _e('Clear All Caches', 'enterprise-ajax-cache'); ?></h3>
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
						<h3><?php _e('Clear Specific Cache', 'enterprise-ajax-cache'); ?></h3>
						<form method="post" action="">
							<?php wp_nonce_field('ajax_cache_clear_specific'); ?>

							<?php
							$settings = $this->get_settings();
							$cacheable_actions = $settings['cacheable_actions'];

							if (empty($cacheable_actions)) {
								echo '<p>' . __('No AJAX actions are currently configured for caching.', 'enterprise-ajax-cache') . '</p>';
							} else {
								echo '<p>' . __('Select an AJAX action to clear its cache:', 'enterprise-ajax-cache') . '</p>';
								echo '<p>';
								echo '<select name="cache_action" id="cache_action">';
								foreach ($cacheable_actions as $action) {
									echo '<option value="' . esc_attr($action) . '">' . esc_html($action) . '</option>';
								}
								echo '</select>';
								echo '</p>';
								echo '<p>';
								echo '<input type="submit" name="clear_specific_cache" id="clear_specific_cache" class="button button-secondary" ';
								echo 'value="' . esc_attr__('Clear Selected Cache', 'enterprise-ajax-cache') . '">';
								echo '</p>';
							}
							?>
						</form>
					</div>

					<div class="card">
						<h3><?php _e('Export Settings', 'enterprise-ajax-cache'); ?></h3>
						<p><?php _e('Export your current AJAX Cache configuration as a JSON file.', 'enterprise-ajax-cache'); ?></p>
						<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
							<input type="hidden" name="action" value="ajax_cache_export_settings">
							<?php wp_nonce_field('ajax_cache_export_settings'); ?>
							<p>
								<input type="submit" name="export_settings" class="button button-secondary"
								       value="<?php _e('Export Settings', 'enterprise-ajax-cache'); ?>">
							</p>
						</form>
					</div>

					<div class="card">
						<h3><?php _e('Import Settings', 'enterprise-ajax-cache'); ?></h3>
						<p><?php _e('Import AJAX Cache configuration from a JSON file.', 'enterprise-ajax-cache'); ?></p>
						<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" enctype="multipart/form-data">
							<input type="hidden" name="action" value="ajax_cache_import_settings">
							<?php wp_nonce_field('ajax_cache_import_settings'); ?>
							<p>
								<input type="file" name="settings_file" accept=".json">
							</p>
							<p>
								<input type="submit" name="import_settings" class="button button-secondary"
								       value="<?php _e('Import Settings', 'enterprise-ajax-cache'); ?>">
							</p>
						</form>
					</div>
				<?php endif; ?>
			</div>
		</div>

		<style>
            .card {
                background: #fff;
                border: 1px solid #c3c4c7;
                border-radius: 2px;
                padding: 20px;
                margin-top: 20px;
                max-width: 800px;
                box-shadow: 0 1px 1px rgba(0,0,0,0.04);
            }
            .card h2, .card h3 {
                margin-top: 0;
            }
		</style>
		<?php
	}

	/**
	 * Get the name of a log level
	 */
	private function get_level_name($level) {
		switch ($level) {
			case Ajax_Cache_Logger::LOG_ERROR:
				return 'ERROR';
			case Ajax_Cache_Logger::LOG_WARNING:
				return 'WARNING';
			case Ajax_Cache_Logger::LOG_INFO:
				return 'INFO';
			case Ajax_Cache_Logger::LOG_DEBUG:
				return 'DEBUG';
			default:
				return 'UNKNOWN';
		}
	}
}

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

// Initialize the plugin
function enterprise_ajax_cache_init() {
	$plugin = Enterprise_AJAX_Cache::get_instance();

	// Add example hooks - typically you'd comment this out in production
	$plugin->add_example_hooks();
}
add_action('plugins_loaded', 'enterprise_ajax_cache_init');

// Register uninstall hook
register_uninstall_hook(__FILE__, ['Enterprise_AJAX_Cache', 'uninstall']);

// Custom logging based on log destination setting
function ajax_cache_custom_logging($message, $level, $context) {
	$settings = Enterprise_AJAX_Cache::get_instance()->get_plugin_settings();

	// Only log if the level is appropriate
	if ($level > $settings['log_level']) {
		return;
	}

	// Format the log message
	$timestamp = current_time('mysql');
	$level_name = _ajax_cache_get_level_name($level);
	$log_message = sprintf("[%s] [%s] %s", $timestamp, $level_name, $message);

	if (!empty($context)) {
		$log_message .= ' ' . json_encode($context);
	}

	// Log based on destination
	switch ($settings['log_destination']) {
		case 'wp_debug':
			// Already handled by the main logger class
			break;

		case 'database':
			// Store in database
			$logs = get_option('ajax_cache_logs', array());
			array_unshift($logs, array(
				'timestamp' => $timestamp,
				'level' => $level,
				'message' => $message,
				'context' => $context
			));

			// Trim to max entries
			if (count($logs) > $settings['log_max_entries']) {
				$logs = array_slice($logs, 0, $settings['log_max_entries']);
			}

			update_option('ajax_cache_logs', $logs);
			break;

		case 'file':
			// Write to custom log file
			$log_file = isset($settings['log_file_path']) ? $settings['log_file_path'] : WP_CONTENT_DIR . '/ajax-cache-logs.log';
			error_log($log_message . PHP_EOL, 3, $log_file);
			break;
	}
}
add_action('ajax_cache_logged', 'ajax_cache_custom_logging', 10, 3);

/**
 * Helper to get level name
 */
function _ajax_cache_get_level_name($level) {
	switch ($level) {
		case Ajax_Cache_Logger::LOG_ERROR:
			return 'ERROR';
		case Ajax_Cache_Logger::LOG_WARNING:
			return 'WARNING';
		case Ajax_Cache_Logger::LOG_INFO:
			return 'INFO';
		case Ajax_Cache_Logger::LOG_DEBUG:
			return 'DEBUG';
		default:
			return 'UNKNOWN';
	}
}
