<?php
/**
 * Plugin Name: HITWP Security
 * Description: HITWP Security toolbox. Should be doing a lot of stuff when it goes stable.
 * Version: 0.0.1a
 * Author: HITWP
 */

class HITWPSecurity {
    private $table_name;

    public function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'hits_ip_limiter';

        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));

        add_action('user_register', array($this, 'record_user_registration_ip'));
        add_filter('registration_errors', array($this, 'validate_user_registration'));
        add_action('admin_menu', array($this, 'admin_menu'));

        // Schedule the cleanup task to run daily at 1 AM.
        if (!wp_next_scheduled('hitwp_security_cleanup')) {
            wp_schedule_event(strtotime('1:00 AM'), 'daily', 'hitwp_security_cleanup');
        }
        add_action('hitwp_security_cleanup', array($this, 'cleanup_old_records'));
    }

    public function activate() {
        $this->create_ip_limiter_table();
    }

    public function deactivate() {
        $this->delete_ip_limiter_table();
    }

    public function create_ip_limiter_table() {
        global $wpdb;

        // SQL query to create the custom table with an unsigned 'id' column
        $sql = "CREATE TABLE $this->table_name (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(255) NOT NULL,
            registration_date DATE NOT NULL,
            PRIMARY KEY (id)
        )";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }

    public function delete_ip_limiter_table() {
        global $wpdb;

        // SQL query to delete the custom table
        $sql = "DROP TABLE IF EXISTS $this->table_name";

        $wpdb->query($sql);
    }

    public function record_user_registration_ip($user_id) {
        global $wpdb;
        $ip = $_SERVER['REMOTE_ADDR'];

        // Record the IP address and registration date in the custom table
        $wpdb->insert($this->table_name, array(
            'ip_address' => $ip,
            'registration_date' => current_time('mysql', 1),
        ));
    }

    public function is_ip_over_limit() {
        global $wpdb;
        $ip = $_SERVER['REMOTE_ADDR'];
        $table_name = $wpdb->prefix . 'hits_ip_limiter';

        $limit = get_option('hitwp_security_registration_limit', 5); // Get the registration limit from settings.

        // Count the number of registrations for the IP address in the current day
        $today = date('Y-m-d');
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table_name WHERE ip_address = %s AND registration_date = %s",
            $ip,
            $today
        ));

        // Check if the count is over the limit
        return $count >= $limit;
    }

    public function validate_user_registration($errors) {
        if ($this->is_ip_over_limit()) {
            $errors->add('registration_error', 'You have reached the registration limit from your IP address.');
            
            // Check if WordFence integration is enabled
            $wordfence_integration = get_option('hitwp_security_wordfence_integration', false);
            if ($wordfence_integration) {
                $ip = $_SERVER['REMOTE_ADDR'];
                // Use WordFence API to block the IP address
                // You need to use WordFence's API for this part.
                // The code below is a placeholder, and you should replace it with WordFence API calls.
                if (function_exists('wordfence_block_ip')) {
                    wordfence_block_ip($ip);
                }
            }
        }
        return $errors;
    }

    public function admin_menu() {
        add_menu_page('HITWP Security Settings', 'HITWP Security', 'manage_options', 'hitwp_security_settings', array($this, 'settings_page'));
    }

    public function settings_page() {
        if (isset($_POST['update_registration_limit'])) {
            check_admin_referer('hitwp_security_nonce');
            $limit = intval($_POST['registration_limit']);
            update_option('hitwp_security_registration_limit', $limit);
        }

        if (isset($_POST['update_wordfence_integration'])) {
            check_admin_referer('hitwp_security_nonce');
            $wordfence_integration = isset($_POST['wordfence_integration']) ? 1 : 0;
            update_option('hitwp_security_wordfence_integration', $wordfence_integration);
        }

        $limit = get_option('hitwp_security_registration_limit', 5);
        $wordfence_integration = get_option('hitwp_security_wordfence_integration', false);

        ?>

        <div class="wrap">
            <h2>HITWP Security Settings</h2>
            <form method="post">
                <?php wp_nonce_field('hitwp_security_nonce'); ?>
                <label for="registration_limit">Registration Limit:</label>
                <input type="number" id="registration_limit" name="registration_limit" value="<?php echo esc_attr($limit); ?>" /><br><br>
                <label for="wordfence_integration">WordFence Integration:</label>
                <input type="checkbox" id="wordfence_integration" name="wordfence_integration" value="1" <?php checked($wordfence_integration, 1); ?> /><br><br>
                <input type="submit" name="update_registration_limit" value="Update Settings" class="button button-primary" />
            </form>
        </div>
        <?php
    }

    public function cleanup_old_records() {
        global $wpdb;

        // Calculate the date from 1 month ago
        $one_month_ago = date('Y-m-d', strtotime('-1 month'));

        // SQL query to delete records older than 1 month
        $sql = $wpdb->prepare("DELETE FROM $this->table_name WHERE registration_date < %s", $one_month_ago);

        $wpdb->query($sql);
    }
}

$hitwp_security = new HITWPSecurity();
