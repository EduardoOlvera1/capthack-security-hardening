<?php
/*
Plugin Name: CaptHack Security Hardening
Plugin URI: https://capturethehack.com.mx/
Description: This plugin helps you hardening your wordpress website. Based on Acunetix Web Scan
Version: 0.9.5
Text Domain: capthack-security-hardening
Author: Eduardo@CTH

Capthack Security Hardening - Fixes some wordpress security
Copyright (C) <2022>  <Eduardo@CTH>
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

function plugin_settings_page() {
    add_menu_page(
        'CTH Hardening', // Menu title
        'CTH Hardening', // Menu name
        'manage_options',
        'cth-hardening',    
        'wp_catphack_security_settings_display',
        'dashicons-lock',
        90 // Menu position
    );

    add_submenu_page(
        'cth-hardening', // Parent slug
        'Plugin Version Checker', // Page title
        'Plugin Version Checker', // Menu title
        'manage_options',
        'wp-catphack-plugin-checker',
        'wp_capthack_plugin_info_page'
    );

    //add_menu_page('Plugin Versions', 'Plugin Versions', 'manage_options', 'plugin_version_checker', 'plugin_info_page');

    add_options_page(
        'Capthack Security Hardening',
        'Capthack Security Hardening',
        'manage_options',
        'wp_capthack_security_settings_menu',
        'wp_catphack_security_settings_display'
    );
}

add_action('admin_menu', 'plugin_settings_page');

function get_plugin_info() {
    $plugins = get_plugins();
    // Loop through the plugins and store their information in an array
    $plugin_info = array();
    foreach ($plugins as $plugin_file => $plugin_data) {
        $plugin_info[$plugin_file] = array(
            'Name' => $plugin_data['Name'],
            'Version' => $plugin_data['Version']
        );
    }
    return $plugin_info;
}

function check_plugin_updates() {
    $update_plugins = get_site_transient('update_plugins');
    // Loop through the updates and store their information in an array
    $plugin_updates = array();
    if (!empty($update_plugins->response)) {
        foreach ($update_plugins->response as $plugin_file => $update_data) {
            $plugin_updates[$plugin_file] = array(
                'Name' => $update_data->slug,
                'New Version' => $update_data->new_version,
                'Released' => $update_data->last_updated
            );
        }
    }
    return $plugin_updates;
}

function wp_catphack_plugin_style(){
    $style = <<<html
    <style>
    .plugin-table {
       width: 100%;
       border-collapse: collapse;
       margin-top: 20px;
    }
    .plugin-table th,
    .plugin-table td {
       padding: 10px;
       border: 1px solid #ddd;
    }
    .plugin-table th {
       background-color: #f5f5f5;
       font-weight: bold;
       text-align: left;
    }
    .plugin-table td.update {
       color: red;
    }
    </style>
    html;
    return $style;
}

function wp_capthack_plugin_info_page() {
    echo wp_catphack_plugin_style();
    $plugin_info = get_plugin_info();
    $plugin_updates = check_plugin_updates();
    // Display the plugin information in a table format
    echo '<h1>Plugin Version Checker @ CTH</h1>';
    echo '<table class="plugin-table">';
    echo '<thead><tr><th>Plugin Name</th><th>Version</th><th>Update</th></tr></thead>';
    echo '<tbody>';
    foreach ($plugin_info as $plugin_file => $plugin_data) {
       echo '<tr>';
       echo '<td>' . $plugin_data['Name'] . '</td>';
       echo '<td>' . $plugin_data['Version'] . '</td>';
       if (isset($plugin_updates[$plugin_file])) {
           echo '<td class="update">' . $plugin_updates[$plugin_file]['New Version'] . '</td>';
       } else {
           echo '<td>-</td>';
       }
       echo '</tr>';
    }
    echo '</tbody></table>';
}

function wp_catphack_security_settings_display(){
    if ( !current_user_can( 'manage_options' ) )  {
        wp_die( __( 'You do not have sufficient permissions to access this page.' ) );
    }
    ?>
    <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
        <form method="post" action="options.php">
            <?php
                settings_fields('cth-hardening');
                do_settings_sections('cth-hardening');
            ?>
        <table class="form-table">
          <tbody>
            <tr>
              <th scope="row">
                <label for="enable-csrf-token">Integration with CF7 (CSRF Token, High Recaptcha Threshold, Special char validation)</label>
              </th>
              <td>
                <input type="checkbox" name="wp_capthack_integration_cf7" id="enable-csrf-token" <?php checked(get_option('wp_capthack_integration_cf7'), 'on'); ?>>
              </td>
            </tr>
            <tr>
              <th scope="row">
                <label for="secure-headers">Enable Secure Headers</label>
              </th>
              <td>
                <input type="checkbox" name="wp_capthack_secure_headers" id="secure-headers" <?php checked(get_option('wp_capthack_secure_headers'), 'on'); ?>>
              </td>
            </tr>
            <!--tr>
              <th scope="row">
                <label for="htaccess-hardening">Htaccess Hardening</label>
              </th>
              <td>
                <input type="checkbox" name="wp_capthack_htaccess_hardening" id="htaccess-hardening" <?php //   checked(get_option('wp_capthack_htaccess_hardening'), 'on'); ?>>
              </td>
            </tr-->
            <tr>
              <th scope="row">
                <label for="rest-api-access">Restrict REST API Access</label>
              </th>
              <td>
                <input type="checkbox" name="wp_catphack_restrict_rest_api_access" id="rest-api-access" <?php checked(get_option('wp_catphack_restrict_rest_api_access'), 'on'); ?>>
              </td>
            </tr>
            <tr>
              <th scope="row">
                <label for="rest-api-cors">CORS Policy Rest API</label>
              </th>
              <td>
                <input type="checkbox" name="wp_capthack_rest_api_cors" id="rest-api-cors" <?php checked(get_option('wp_capthack_rest_api_cors'), 'on'); ?>>
              </td>
            </tr>
            <tr>
              <th scope="row">
                <label for="iframe-sandbox">Sandbox Attribute on iFrame</label>
              </th>
              <td>
                <input type="checkbox" name="wp_capthack_sandbox_attribute" id="iframe-sandbox" <?php checked(get_option('wp_capthack_sandbox_attribute'), 'on'); ?>>
              </td>
            </tr>
            <tr>
              <th scope="row">
                <label for="postpass-timeout">Protected Page Cookie Timeout</label>
              </th>
              <td>
                <input type="text" name="wp_capthack_postpass_timeout_time" id="postpass-timeout" value="<?php echo(get_option( 'wp_capthack_postpass_timeout_time', '10'))?>">
                <select name="wp_capthack_postpass_timeout_time_type" id="postpass-timeout-type">
                    <option value="seconds" <?php selected(get_option( 'wp_capthack_postpass_timeout_time_type'), 'seconds')  ?>>Seconds</option>
                    <option value="minutes" <?php selected(get_option( 'wp_capthack_postpass_timeout_time_type'), 'minutes')  ?>>Minutes</option>
                    <option value="hours" <?php selected(get_option( 'wp_capthack_postpass_timeout_time_type'), 'hours')  ?>>Hours</option>
                    <option value="days" <?php selected(get_option( 'wp_capthack_postpass_timeout_time_type'), 'days')  ?>>Days</option>
                </select>
              </td>
            </tr>
          </tbody>
        </table>
        <?php submit_button(); ?>
      </form>
    </div>
    <?php
}

function wp_capthack_settings() {
    register_setting('cth-hardening', 'wp_capthack_integration_cf7');
    register_setting('cth-hardening', 'wp_capthack_htaccess_hardening');
    register_setting('cth-hardening', 'wp_catphack_restrict_rest_api_access');
    register_setting('cth-hardening', 'wp_capthack_rest_api_cors');
    register_setting('cth-hardening', 'wp_capthack_sandbox_attribute');
    register_setting('cth-hardening', 'wp_capthack_secure_headers');
    register_setting('cth-hardening', 'wp_capthack_disable_xmlrpc');
    register_setting('cth-hardening', 'wp_capthack_disable_user_enumeration');
    register_setting('cth-hardening', 'wp_capthack_disable_login_form_autocomplete');
    register_setting('cth-hardening', 'wp_capthack_postpass_timeout_time', array('default' => '10', 'type' => 'string'));
    register_setting('cth-hardening', 'wp_capthack_postpass_timeout_time_type', array('default' => 'days', 'type' => 'string'));

}

add_action('admin_init', 'wp_capthack_settings');

//Widget CTH

function wp_capthack_widget_function() {
	wp_add_dashboard_widget(
		'wp_catphack_widget',
		'Capthack Security Hardening',
		'wp_capthack_widget_fill_content'
	);
}

add_action('wp_dashboard_setup', 'wp_capthack_widget_function');

function wp_capthack_widget_fill_content() {

    $headers = wp_get_http_headers( get_home_url());
    $headers_current = $headers->getAll();

    $headers_to_check = ["x-frame-options",
        "x-powered-by",
        "access-control-allow-methods",
        "content-security-policy",
        "x-content-type-options",
        "strict-transport-security",
        "x-xss-protection",
        "set-cookie"    
    ];

    echo "<h2>Headers check</h2>";

    $good = "<span style='color:green; font-weight: bold'>Configuracion correcta: </span>";
    $bad = "<span style='color:red; font-weight: bold'>Configuracion incorrecta: </span>";
    $not_found = "<span style='color:red; font-weight: bold'>No existe el header: </span>";

    foreach( $headers_to_check as $key){
        
        $header_value = $headers_current[$key];

        if ( is_array( $header_value ) ){
            break;
        }

        if ( ! isset( $header_value ))
            if ( $key === "x-powered-by")
                echo $good;
            else
                echo $not_found;
        
        switch($key){
            case "x-frame-options":
                if ( $header_value === "SAMEORIGIN")
                    echo $good;
                else
                    echo $bad;
                break;
            case "access-control-allow-methods":
                if ( $header_value === "GET,PUT,POST")
                    echo $good;
                else
                    echo $bad; 
                break;
            case "content-security-policy":
                if ( strpos($header_value, "frame-ancestors 'self'") !== false )
                    echo $good;
                else
                    echo $bad;
                break;   
            case "x-content-type-options":
                if ( $header_value === "nosniff" )
                    echo $good;
                else
                    echo $bad;
                break;
            case "strict-transport-security":
                echo $good;
                break;
            case "x-xss-protection":
                if ( $header_value === "1; mode=block")
                    echo $good;
                else 
                    echo $bad;
                break;
            case "set-cookie":
                if ( strpos($header_value, "HttpOnly") !== false )
                    echo $good;
                else
                    echo $bad;
                break;
        }

        echo strtoupper ( $key ) . " = " . $header_value;

        echo "</p>";    
    }
}

//Settings Link

add_filter( 'plugin_action_links_' . plugin_basename(__FILE__), 'wp_catphack_settings_link' );

function wp_catphack_settings_link( array $links ) {
    $url = get_admin_url() . "admin.php?page=cth-hardening";
    $settings_link = '<a href="' . $url . '">' . __('Settings', 'textdomain') . '</a>';
    $links[] = $settings_link;
    return $links;
}

//HTACCESS REWRITE

function wp_capthack_htaccess_mod( $rules ){
    $ownRules = <<<EOD
    #Capthack Security Hardening\n\n
    Options -Indexes
    <IfModule mod_headers.c>
    Header always edit Set-Cookie ^(.*) "$1; HttpOnly"
    Header always edit Set-Cookie ^(.*) "$1; Secure"
    Header always edit Set-Cookie ^(.*) "$1; SameSite=Lax"
    Header always set X-Frame-Options SAMEORIGIN
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    </IfModule>
    <FilesMatch "\.(html|psd|log|sh|ini|txt|json)$">
        Order allow,deny
        Deny from all
    </FilesMatch>
    <FilesMatch "xmlrpc\.php">
    	Order allow,deny
        Deny from all
    </FilesMatch>\n
    #END Capthack Security Hardening\n\n
    EOD;

    return $ownRules . $rules;
}

add_filter('mod_rewrite_rules', 'wp_capthack_htaccess_mod');

function wp_catphack_write_htaccess_rules(){
    global $wp_rewrite;
    $wp_rewrite->flush_rules();
}

#Acciona la function cuando se activa el plugin
register_activation_hook( __FILE__, 'wp_catphack_write_htaccess_rules');

function wp_catphack_remove_htaccess_rules(){
    remove_filter('mod_rewrite_rules', 'wp_capthack_htaccess_mod');
    global $wp_rewrite;
    $wp_rewrite->flush_rules();
}
#Acciona cuando se desactiva el plugin
register_deactivation_hook( __FILE__, 'wp_catphack_remove_htaccess_rules');

/*Remove default CORS Headers*/

add_action('rest_api_init', function() {
    remove_filter('rest_pre_serve_request', 'rest_send_cors_headers');
}, 15);

/* 

REST API Custom Response Headers

** Places CORS headers on the API response

*/
function wp_capthack_header_rest_response($result, $server, $request){ 

    if ( get_option( 'wp_capthack_rest_api_cors' ) !== "on" ){
        return $result;
    }

    $result->header('Access-Control-Allow-Origin', get_home_url());
    $result->header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    $result->header('Access-Control-Allow-Headers', 'Content-Type');
    $result->header('Access-Control-Max-Age', '86400');
    return $result;
}

add_filter( 'rest_post_dispatch', 'wp_capthack_header_rest_response', 10, 4);

function wp_capthack_header_send() {

    if (get_option( 'wp_capthack_secure_headers' ) !== "on"){
        return $headers;
    }

	header( 'X-XSS-Protection: 1; mode=block' );
	header( 'Expect-CT: max-age=7776000, enforce' );
	header( 'Access-Control-Allow-Origin: null' );
	header( 'Access-Control-Allow-Methods: GET,PUT,POST' );
	header( 'Access-Control-Allow-Headers: Content-Type, Authorization' );
	header( 'X-Content-Security-Policy: default-src "self"; img-src *; media-src * data:;' );
    header( 'X-Content-Type-Options: nosniff' );
	header( "Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data: blob:" . "; frame-ancestors 'self' " );
	header( 'Referrer-Policy: strict-origin-when-cross-origin' );
	header( 'Cross-Origin-Embedder-Policy-Report-Only: unsafe-none; report-to="default"' );
	header( 'Cross-Origin-Embedder-Policy: unsafe-none; report-to="default"' );
	header( 'Cross-Origin-Opener-Policy-Report-Only: same-origin; report-to="default"' );
	header( 'Cross-Origin-Opener-Policy: same-origin-allow-popups; report-to="default"' );
    header( 'Cross-Origin-Resource-Policy: cross-origin' );
    header( "Feature-Policy: display-capture 'self'");
    header( 'X-Permitted-Cross-Domain-Policies: none' );
}

add_action( 'send_headers', 'wp_capthack_header_send' );

//Disable XML-RPC
function wp_capthack_disable_xml_rpc(){

    if ( get_option('wp_capthack_disable_xmlrpc') !== "on" ){
        return;
    }

    if(substr_count(strtolower($_SERVER['REQUEST_URI']), strtolower('xmlrpc'))){
        die();
    }

    add_filter('xmlrpc_enabled', '__return_false');

    add_filter('wp_headers', 'wp_capthack_disable_x_pingback');
	
    function wp_capthack_disable_x_pingback( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}
}

add_action('init', 'wp_capthack_disable_xml_rpc');


//Disable WP-JSON API
add_filter('rest_authentication_errors', function ($result) {

    $whitelist = ["127.0.0.1", "::1", "fe80::1"];

    if ( is_user_logged_in() ){
        return $result;
    }

    if (str_contains( $_SERVER['HTTP_REFERER'], $_SERVER['SERVER_NAME'] )){
        return $result;
    }

    if ( ! empty( $result ) ) {
        return $result;
    }
	
	if ( strcmp( $_SERVER['HTTP_ORIGIN'], get_home_url()) == 0){
    	return $result;
    }

    if ( ! is_user_logged_in() ) {
        return new WP_Error( 'rest_not_logged_in', 'You are not currently logged in.', array( 'status' => 403 ) );
    }

    if ( ! in_array($_SERVER['REMOTE_ADDR'], $whitelist)){
        return new WP_Error( 'rest_not_logged_in', 'You are not currently logged in.', array('status' => 401));
    }

    return $result;
});

function wp_capthack_csrf_generate_hidden_fields( $fields ){

    if ( !isset($_SESSION['wp_capthack_csrf_token'])){
        $_SESSION['wp_capthack_csrf_token'] = wp_create_nonce( 'wp_capthack_cf7_csrf' );
    }

    $fields['csrf_token'] = $_SESSION['wp_capthack_csrf_token'];

    return $fields;

}

function wp_capthack_handle_contact_form_submission( $contact_form, &$abort, $submission ){

    $token = $submission->get_posted_data('csrf_token');

    if ( !wp_capthack_validate_csrf_token($token) ){
        $abort = true;
        $submission->set_response($contact_form->filter_message(__("Blocked request", "contact-form-7")));
    }

    return $contact_form;
}

function wp_capthack_custom_input_validation( $result, $tag ){

    $tags = array("your-name");

    foreach ($tags as $tag_name){
        if ( $tag_name == $tag->name){
            $post_field = isset( $_POST[$tag_name] ) ? trim( $_POST[$tag_name] ) : '';
            if ( ! ctype_alpha( $post_field ) ){
                $result->invalidate($tag, "No se aceptan caracteres especiales");
            }
        }
    }

    return $result;
}

function wp_capthack_modify_captcha_threshold( $threshold ){
    $threshold = 0.7;
    return $threshold;
}


if (!function_exists('is_plugin_active')) {
    include_once(ABSPATH . 'wp-admin/includes/plugin.php');
}

if (is_plugin_active("contact-form-7/wp-contact-form-7.php")){
    if (get_option( 'wp_capthack_integration_cf7' ) === "on"){
        add_filter( 'wpcf7_validate_text*', 'wp_capthack_custom_input_validation', 20, 2);
        add_filter( 'wpcf7_form_hidden_fields', 'wp_capthack_csrf_generate_hidden_fields', 10, 1);
        add_action( 'wpcf7_before_send_mail', 'wp_capthack_handle_contact_form_submission', 10, 3);
        add_filter( 'wpcf7_recaptcha_threshold', 'wp_capthack_modify_captcha_threshold', 10, 1);
    }
}

function wp_capthack_disable_login_autocomplete(){

    echo <<<html
    <script>
    var inputElements = document.getElementsByTagName('input')
    for (const i in inputElements){
        inputElements[i].autocomplete = 'off'
    }
    </script>
    html;
}

add_action( 'login_form', 'wp_capthack_disable_login_autocomplete', 9);

function wp_capthack_login_form_token_generation(){

    $token = wp_create_nonce( 'wp_capthack_csrf' );
    wp_nonce_field( 'wp_capthack_csrf', 'token-field' );

}

add_action( 'login_form', 'wp_capthack_login_form_token_generation', 10);

function wp_capthack_handle_login_form_submission( $user ){

    if ($_SERVER['REQUEST_METHOD'] === 'GET'){
        return $user;
    }

    if ( !isset( $_POST['token-field'] ) ){
        $user = new WP_Error('denied', __("Access denied: Invalid request...") );
    }

    if (!wp_verify_nonce( $_POST['token-field'], 'wp_capthack_csrf' )){ 
        $user = new WP_Error('denied', __("Access denied: Invalid request...") );
    }

    return $user;

}

add_filter( 'authenticate', 'wp_capthack_handle_login_form_submission', 20, 1);

function wp_capthack_disable_media_comments( $open, $post_id ){
    $post = get_post( $post_id );
    if( $post->post_type == 'attachment' ) {
        return false;
    }
    return $open;
}

add_filter( 'comments_open', 'wp_capthack_disable_media_comments', 10 , 2 );

function wp_capthack_validate_csrf_token( $token ): bool {

    if (!isset($token)){
        return false;
    }

    if (wp_verify_nonce( $token, 'wp_capthack_cf7_csrf' )){
    	return true;
    }

    if ($_SESSION['wp_capthack_csrf_token'] === $token) {
        return true;
    }
    
    return false;
}

/**
 * 
 * Method for changing the time on the protected page timeout
 * 
 **/

 function wp_capthack_change_timeout( $expires ){

    $custom_time = get_option( 'wp_capthack_postpass_timeout_time' );
    $custom_time_type = get_option( 'wp_capthack_postpass_timeout_time_type' );

    if ($custom_time === '10' && $custom_time_type === 'days'){
        return $expires;
    }

    if ($custom_time_type === 'seconds'){
        return time() + (int) $custom_time;
    } else if ($custom_time_type === 'minutes'){
        $timeMinutes = 60 * (int) $custom_time;
        return time() + $timeMinutes;
    } else if ($custom_time_type === 'hours'){
        $timeHours = 3600 * (int) $custom_time;
        return time() + $timeHours;
    } else {
        $timeDays = 86400 * (int) $custom_time;
        return time() + $timeDays;
    }
}

add_filter('post_password_expires', 'wp_capthack_change_timeout' );


/***
 * 
 * Method for placing sandbox attribute into oEmbed Wordpress Shorcuts aka iFrame HTML tags
 * Not implemented
 * 
 * 
***/

function wp_capthack_place_sandbox_attribute_oembed($html, $data, $url){

    if ( get_option( 'wp_capthack_sandbox_attribute' ) !== 'on'){
        return $html;
    }

    if ( strpos($html, 'sandbox') !== false ){
        return $html;
    }

    $html_parts = explode('>', $html, 3);

    $final_embed_content = '';

    if ( $data->type === 'video' || $data->type === 'link' ){
        $final_embed_content = $html_parts[0] . ' sandbox="allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"';
    } else {
        $final_embed_content = $html_parts[0];
    }

    return $final_embed_content . '></iframe>';

}

/**
 * 
 * $args: PLL_Cookie
 * Filter to alter 'pll_cookie' flags
 * 
 */

function wp_catphack_add_polylang_http_only_cookie_flag( $args ) {

    $cookie_params = array('httponly' => TRUE);
    $merged_cookie_params = wp_parse_args( $cookie_params, $args );
    return $merged_cookie_params;
}

add_filter('pll_cookie_args', 'wp_catphack_add_polylang_http_only_cookie_flag');

/*
 *
 * Methods to remove iFrame cache
 * 
 */

add_filter( 'oembed_dataparse', 'wp_capthack_place_sandbox_attribute_oembed', 99, 4);

add_filter( 'oembed_ttl', function($ttl) {
	  $GLOBALS['wp_embed']->usecache = 0;
            $ttl = 0;
            // House-cleanoing
            do_action( 'wpse_do_cleanup' );
	return $ttl;
});

add_filter( 'embed_oembed_discover', function( $discover )
{
    if( 1 === did_action( 'wpse_do_cleanup' ) )
        $GLOBALS['wp_embed']->usecache = 1;
    return $discover;
} ); 


?>