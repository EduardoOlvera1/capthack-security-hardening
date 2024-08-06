Changelog
### 0.9.3
* Added: Filter to change pll_cookie flags (httpOnly)

### 0.9.2

* Replaced: wp_headers hook to send_headers action
* Changed: Pre defined Content-Security-Policy header
* Removed: Disable Users enum function ***caused problems on wp 6.4***

### 0.9.1

* Added: Optional function to remove URI parameters

### 0.9

* Added: Function to auto generate sandbox attribute on oEmbed elements ***only on multimedia***

### 0.8
* Added: UI
* Added: Option page to check plugin version and updates
* Added: Option page to activate and deactivate some features

### 0.7.1

* Changed: CSRF token generation to wp_create_nonce() function

### 0.7

* Added:Creation of hidden input with csrf token
* Added: CSRF validation on main admin login form
* Modified: Renamed ContactForm7 validation function from "wp_catphack_validate_csrf_token" to "wp_capthack_handle_contact_form_submission"
* Individual function to validate CSRF Token, can be used in other functions/hooks by plugin itself

### 0.6.1:
- Fixed: Rejecting Elementor API Call on Edit Page

### 0.6:
- Fixed: When creating multiple forms, csrf token didnt match and cause a 403 error as a response

### 0.5:
- Added a custom function to remove media comments
- Added a custom function to increase the default CF7 reCAPTCHA threshold to 0.7

### 0.4:

- Added: Custom validation on inputs (WPCF7)

### 0.3

- Added: Custom error message on validating csrf token (WPCF7)