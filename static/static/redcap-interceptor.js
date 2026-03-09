/**
 * REDCap Form Validation Interceptor
 * 
 * This script intercepts the "Save & Go To Next Form" button
 * and validates the form data before allowing submission.
 * 
 * Add this to your REDCap form's HTML or inject via browser extension
 */

(function() {
    'use strict';
    
    // Configuration
    const CONFIG = {
        VALIDATION_API_URL: 'http://127.0.0.1:5000/api/validate-on-submit',
        DEBUG_MODE: true,  // Set to false in production
        TIMEOUT_MS: 10000, // 10 second timeout
        ALLOW_FALLBACK: true // If validation server is down, proceed anyway
    };
    
    // Track if we're already processing to prevent double-clicks
    let isProcessing = false;
    
    /**
     * Initialize the interceptor when DOM is ready
     */
    function init() {
        log('🔧 Initializing REDCap form interceptor');
        
        // Wait a bit for the page to fully load
        setTimeout(findAndInterceptButton, 500);
        
        // Also try on DOMContentLoaded
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', findAndInterceptButton);
        } else {
            findAndInterceptButton();
        }
        
        // Watch for dynamically added buttons (rare, but possible)
        const observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.addedNodes.length) {
                    findAndInterceptButton();
                }
            });
        });
        
        observer.observe(document.body, { childList: true, subtree: true });
    }
    
    /**
     * Find the "Save & Go To Next Form" button and attach event listener
     */
    function findAndInterceptButton() {
        // Look for the button by its value attribute
        const saveAndNextBtn = document.querySelector('input[value="Save & Go To Next Form"]');
        
        if (saveAndNextBtn && !saveAndNextBtn.hasAttribute('data-validation-attached')) {
            log('✅ Found "Save & Go To Next Form" button');
            
            // Mark as attached to prevent duplicate listeners
            saveAndNextBtn.setAttribute('data-validation-attached', 'true');
            
            // Store original click handler if any
            const originalClick = saveAndNextBtn.onclick;
            
            // Remove any existing listeners (we'll use our own)
            saveAndNextBtn.onclick = null;
            
            // Add our interceptor
            saveAndNextBtn.addEventListener('click', handleSaveAndNextClick);
            
            log('🔄 Interceptor attached to button');
        }
    }
    
    /**
     * Handle click on Save & Go To Next Form button
     */
    async function handleSaveAndNextClick(event) {
        // Prevent default form submission
        event.preventDefault();
        
        // Prevent double-processing
        if (isProcessing) {
            log('⏳ Already processing, ignoring double-click');
            return false;
        }
        
        isProcessing = true;
        
        try {
            // Show loading indicator
            showLoadingIndicator('Validating form data...');
            
            // Collect all form data
            const formData = collectFormData();
            
            // Get record ID
            const recordId = getRecordId();
            
            // Get current form name
            const currentForm = getCurrentForm();
            
            // Get next form name
            const nextForm = getNextForm();
            
            // Get current user (if available)
            const username = getCurrentUser();
            
            // Prepare payload
            const payload = {
                record_id: recordId,
                current_form: currentForm,
                next_form: nextForm,
                username: username,
                device: navigator.userAgent,
                form_data: formData
            };
            
            log('📤 Sending validation request:', payload);
            
            // Set up timeout
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), CONFIG.TIMEOUT_MS);
            
            // Send to validation API
            const response = await fetch(CONFIG.VALIDATION_API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
                signal: controller.signal
            }).catch(error => {
                if (error.name === 'AbortError') {
                    throw new Error('Validation request timed out');
                }
                throw error;
            });
            
            clearTimeout(timeoutId);
            
            // Parse response
            const data = await response.json();
            
            log('📥 Received validation response:', data);
            
            // Hide loading indicator
            hideLoadingIndicator();
            
            // Handle response based on status
            if (data.status === 'blocked') {
                // Critical errors found - block navigation
                showErrorModal(data);
                isProcessing = false;
            } else if (data.status === 'warning') {
                // Warnings found - ask user if they want to proceed
                showWarningModal(data, () => {
                    // User chose to proceed
                    log('➡️ User chose to proceed with warnings');
                    submitForm();
                });
                isProcessing = false;
            } else if (data.status === 'success') {
                // No errors - proceed
                log('✅ Validation passed, proceeding to next form');
                submitForm();
            } else {
                // Unexpected response
                log('⚠️ Unexpected response:', data);
                if (CONFIG.ALLOW_FALLBACK) {
                    showToast('Validation server returned unexpected response. Proceeding anyway...', 'warning');
                    submitForm();
                } else {
                    showErrorModal({
                        message: data.message || 'Validation error occurred',
                        errors: data.errors
                    });
                    isProcessing = false;
                }
            }
        } catch (error) {
            // Handle errors
            log('❌ Error during validation:', error);
            hideLoadingIndicator();
            
            if (error.name === 'AbortError') {
                showToast('Validation request timed out. ', 'error');
            } else {
                showToast('Error connecting to validation server. ', 'error');
            }
            
            if (CONFIG.ALLOW_FALLBACK) {
                showToast('Proceeding with form submission...', 'warning');
                setTimeout(() => {
                    submitForm();
                }, 1500);
            } else {
                showErrorModal({
                    message: 'Could not validate form: ' + (error.message || 'Unknown error'),
                    errors: { critical: [], warnings: [], info: [] }
                });
                isProcessing = false;
            }
        }
    }
    
    /**
     * Collect all form data from the page
     */
    function collectFormData() {
        const formData = {};
        
        // Get all input, select, and textarea elements
        const fields = document.querySelectorAll('input, select, textarea');
        
        fields.forEach(field => {
            // Skip submit buttons, hidden fields that are internal, and disabled fields
            if (field.type === 'submit' || field.type === 'button' || field.disabled) {
                return;
            }
            
            // Get field name and value
            const name = field.name;
            if (!name) return; // Skip fields without name
            
            let value = field.value;
            
            // Handle different input types
            if (field.type === 'checkbox') {
                // For checkboxes, use checked state
                formData[name] = field.checked ? '1' : '0';
            } else if (field.type === 'radio') {
                // For radio groups, only add the checked one
                if (field.checked) {
                    formData[name] = value;
                }
            } else {
                // Default handling
                formData[name] = value;
            }
        });
        
        // Also get any REDCap-specific hidden fields
        const redcapFields = ['__redcap_event_name__', '__redcap_repeat_instance__'];
        redcapFields.forEach(fieldName => {
            const field = document.querySelector(`[name="${fieldName}"]`);
            if (field) {
                formData[fieldName] = field.value;
            }
        });
        
        return formData;
    }
    
    /**
     * Get the current record ID from the page
     */
    function getRecordId() {
        // Try different possible field names
        const possibleSelectors = [
            'input[name="record_id"]',
            'input[name="id"]',
            '#record_id',
            '[data-record-id]'
        ];
        
        for (const selector of possibleSelectors) {
            const field = document.querySelector(selector);
            if (field && field.value) {
                return field.value;
            }
        }
        
        // Try to get from URL
        const urlParams = new URLSearchParams(window.location.search);
        const id = urlParams.get('id');
        if (id) return id;
        
        // Fallback
        return 'UNKNOWN_RECORD';
    }
    
    /**
     * Get the current form name
     */
    function getCurrentForm() {
        // Try from URL parameter
        const urlParams = new URLSearchParams(window.location.search);
        const page = urlParams.get('page');
        if (page) return page;
        
        // Try from form element
        const form = document.querySelector('form');
        if (form && form.id) return form.id;
        
        // Try from page title
        const title = document.querySelector('h1, h2, .form-title');
        if (title) return title.textContent.trim();
        
        return 'unknown_form';
    }
    
    /**
     * Determine the next form in sequence
     * This needs to be customized based on your REDCap project structure
     */
    function getNextForm() {
        // Define your form sequence here - CUSTOMIZE THIS!
        const formSequence = [
            'demographics',
            'registration',
            'prenatal',
            'delivery',
            'postnatal',
            'followup'
        ];
        
        const currentForm = getCurrentForm();
        const currentIndex = formSequence.indexOf(currentForm);
        
        if (currentIndex >= 0 && currentIndex < formSequence.length - 1) {
            return formSequence[currentIndex + 1];
        }
        
        // Try to get from REDCap's internal data
        const nextButton = document.querySelector('input[value="Save & Go To Next Form"]');
        if (nextButton) {
            // Sometimes REDCap stores the next form in a data attribute
            const nextForm = nextButton.getAttribute('data-next-form');
            if (nextForm) return nextForm;
        }
        
        return 'unknown_next';
    }
    
    /**
     * Get the current logged-in user
     */
    function getCurrentUser() {
        // Try different selectors for user info
        const userSelectors = [
            '.user-info',
            '#user-info',
            '.username',
            '#username',
            '[data-user]'
        ];
        
        for (const selector of userSelectors) {
            const element = document.querySelector(selector);
            if (element) {
                return element.textContent.trim();
            }
        }
        
        // Try to get from meta tag
        const metaUser = document.querySelector('meta[name="user"]');
        if (metaUser) {
            return metaUser.getAttribute('content');
        }
        
        return 'unknown_user';
    }
    
    /**
     * Actually submit the form to REDCap
     */
    function submitForm() {
        log('➡️ Submitting form to REDCap');
        
        // Find the form and submit it
        const form = document.querySelector('form');
        if (form) {
            // Remove our event listener temporarily to prevent loop
            const saveAndNextBtn = document.querySelector('input[value="Save & Go To Next Form"]');
            if (saveAndNextBtn) {
                saveAndNextBtn.removeEventListener('click', handleSaveAndNextClick);
            }
            
            // Submit the form
            form.submit();
        } else {
            // If no form found, just navigate to next page
            log('⚠️ No form found, navigating manually');
            window.location.href = getNextFormUrl();
        }
    }
    
    /**
     * Get URL for next form (fallback if form submission fails)
     */
    function getNextFormUrl() {
        const url = new URL(window.location.href);
        const nextForm = getNextForm();
        if (nextForm !== 'unknown_next') {
            url.searchParams.set('page', nextForm);
        }
        return url.toString();
    }
    
    /**
     * Show loading indicator
     */
    function showLoadingIndicator(message = 'Processing...') {
        // Remove existing loader if any
        hideLoadingIndicator();
        
        const loader = document.createElement('div');
        loader.id = 'validation-loader';
        loader.innerHTML = `
            <div style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 999999;
                backdrop-filter: blur(3px);
            ">
                <div style="
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.2);
                    text-align: center;
                    max-width: 400px;
                ">
                    <div style="
                        border: 4px solid #f3f3f3;
                        border-top: 4px solid #3498db;
                        border-radius: 50%;
                        width: 40px;
                        height: 40px;
                        animation: spin 1s linear infinite;
                        margin: 0 auto 20px;
                    "></div>
                    <p style="margin: 0; font-size: 16px; color: #333;">${message}</p>
                </div>
            </div>
            <style>
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
            </style>
        `;
        
        document.body.appendChild(loader);
    }
    
    /**
     * Hide loading indicator
     */
    function hideLoadingIndicator() {
        const existingLoader = document.getElementById('validation-loader');
        if (existingLoader) {
            existingLoader.remove();
        }
    }
    
    /**
     * Show error modal with critical errors
     */
    function showErrorModal(data) {
        const modal = document.createElement('div');
        modal.id = 'validation-modal';
        modal.innerHTML = `
            <div style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 999999;
            ">
                <div style="
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.2);
                    max-width: 600px;
                    max-height: 80vh;
                    overflow-y: auto;
                ">
                    <h2 style="color: #dc3545; margin-top: 0;">❌ Critical Errors Found</h2>
                    <p style="color: #666; margin-bottom: 20px;">${data.message || 'Please fix these errors before proceeding:'}</p>
                    
                    ${formatErrorsForDisplay(data.errors)}
                    
                    <div style="text-align: right; margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee;">
                        <button onclick="document.getElementById('validation-modal').remove()" style="
                            background: #6c757d;
                            color: white;
                            border: none;
                            padding: 10px 20px;
                            border-radius: 5px;
                            cursor: pointer;
                            font-size: 14px;
                        ">Close and Fix</button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
    }
    
    /**
     * Show warning modal with option to proceed
     */
    function showWarningModal(data, onProceed) {
        const modal = document.createElement('div');
        modal.id = 'validation-modal';
        modal.innerHTML = `
            <div style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 999999;
            ">
                <div style="
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.2);
                    max-width: 600px;
                    max-height: 80vh;
                    overflow-y: auto;
                ">
                    <h2 style="color: #ffc107; margin-top: 0;">⚠️ Warnings Found</h2>
                    <p style="color: #666; margin-bottom: 20px;">${data.message || 'You can proceed, but please review these warnings:'}</p>
                    
                    ${formatErrorsForDisplay(data.errors)}
                    
                    <div style="text-align: right; margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee;">
                        <button onclick="document.getElementById('validation-modal').remove()" style="
                            background: #6c757d;
                            color: white;
                            border: none;
                            padding: 10px 20px;
                            border-radius: 5px;
                            cursor: pointer;
                            font-size: 14px;
                            margin-right: 10px;
                        ">Go Back</button>
                        <button onclick="proceedWithWarnings()" style="
                            background: #28a745;
                            color: white;
                            border: none;
                            padding: 10px 20px;
                            border-radius: 5px;
                            cursor: pointer;
                            font-size: 14px;
                        ">Continue Anyway</button>
                    </div>
                </div>
            </div>
        `;
        
        // Add proceed function to window
        window.proceedWithWarnings = function() {
            document.getElementById('validation-modal').remove();
            if (onProceed) onProceed();
        };
        
        document.body.appendChild(modal);
    }
    
    /**
     * Format errors for display in modal
     */
    function formatErrorsForDisplay(errors) {
        let html = '';
        
        if (errors.critical && errors.critical.length > 0) {
            html += '<h3 style="color: #dc3545; margin: 10px 0;">Critical</h3>';
            html += '<ul style="margin-bottom: 20px;">';
            errors.critical.forEach(error => {
                html += `<li style="margin-bottom: 8px;">
                    <strong>${error.field || 'Unknown'}:</strong> ${error.error || error.error_message}
                    <br><small style="color: #666;">${error.suggestion || ''}</small>
                </li>`;
            });
            html += '</ul>';
        }
        
        if (errors.warnings && errors.warnings.length > 0) {
            html += '<h3 style="color: #ffc107; margin: 10px 0;">Warnings</h3>';
            html += '<ul style="margin-bottom: 20px;">';
            errors.warnings.forEach(error => {
                html += `<li style="margin-bottom: 8px;">
                    <strong>${error.field || 'Unknown'}:</strong> ${error.error || error.error_message}
                    <br><small style="color: #666;">${error.suggestion || ''}</small>
                </li>`;
            });
            html += '</ul>';
        }
        
        if (errors.info && errors.info.length > 0) {
            html += '<h3 style="color: #17a2b8; margin: 10px 0;">Info</h3>';
            html += '<ul style="margin-bottom: 20px;">';
            errors.info.forEach(error => {
                html += `<li style="margin-bottom: 8px;">
                    <strong>${error.field || 'Unknown'}:</strong> ${error.error || error.error_message}
                    <br><small style="color: #666;">${error.suggestion || ''}</small>
                </li>`;
            });
            html += '</ul>';
        }
        
        return html;
    }
    
    /**
     * Show toast notification
     */
    function showToast(message, type = 'info') {
        const colors = {
            info: '#17a2b8',
            success: '#28a745',
            warning: '#ffc107',
            error: '#dc3545'
        };
        
        const toast = document.createElement('div');
        toast.id = 'validation-toast';
        toast.innerHTML = `
            <div style="
                position: fixed;
                bottom: 20px;
                right: 20px;
                background: ${colors[type] || colors.info};
                color: white;
                padding: 15px 20px;
                border-radius: 5px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.2);
                z-index: 999999;
                animation: slideIn 0.3s ease;
            ">
                ${message}
            </div>
            <style>
                @keyframes slideIn {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
            </style>
        `;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            const toastEl = document.getElementById('validation-toast');
            if (toastEl) toastEl.remove();
        }, 5000);
    }
    
    /**
     * Log messages if debug mode is enabled
     */
    function log(...args) {
        if (CONFIG.DEBUG_MODE) {
            console.log('🔍 [REDCap Validator]', ...args);
        }
    }
    
    // Initialize when script loads
    if (document.readyState === 'complete') {
        init();
    } else {
        window.addEventListener('load', init);
    }
    
})();