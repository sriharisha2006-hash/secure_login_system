/**
 * Secure Login System - Frontend Interactivity & Validation
 */

document.addEventListener('DOMContentLoaded', () => {
    initPasswordToggles();
    initPasswordStrengthMeter();
    initLockoutCountdown();
    initAlertAutoDismiss();
    initFormSubmitFeedback();
});

/**
 * Password Visibility Toggle
 */
function initPasswordToggles() {
    const toggleButtons = document.querySelectorAll('.btn-toggle-password');
    
    toggleButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = btn.getAttribute('data-target');
            const input = document.getElementById(targetId);
            if (!input) return;

            const eyeOpen = btn.querySelector('.eye-open');
            const eyeClosed = btn.querySelector('.eye-closed');

            if (input.type === 'password') {
                input.type = 'text';
                if (eyeOpen) eyeOpen.classList.add('hidden');
                if (eyeClosed) eyeClosed.classList.remove('hidden');
            } else {
                input.type = 'password';
                if (eyeOpen) eyeOpen.classList.remove('hidden');
                if (eyeClosed) eyeClosed.classList.add('hidden');
            }
        });
    });
}

/**
 * Interactive Password Strength Calculator & Checklist
 */
function initPasswordStrengthMeter() {
    const passwordInput = document.getElementById('password');
    const confirmInput = document.getElementById('confirm_password');
    const strengthBar = document.getElementById('strengthBar');
    const strengthStatus = document.getElementById('strengthStatus');

    if (!passwordInput || !strengthBar || !strengthStatus) return;

    const ruleLength = document.getElementById('rule-length');
    const ruleUpper = document.getElementById('rule-uppercase');
    const ruleLower = document.getElementById('rule-lowercase');
    const ruleDigit = document.getElementById('rule-digit');
    const ruleSpecial = document.getElementById('rule-special');
    const ruleMatch = document.getElementById('rule-match');

    function evaluateStrength() {
        const val = passwordInput.value || '';
        const confirmVal = confirmInput ? confirmInput.value || '' : '';

        // Criteria checks
        const hasLength = val.length >= 8;
        const hasUpper = /[A-Z]/.test(val);
        const hasLower = /[a-z]/.test(val);
        const hasDigit = /[0-9]/.test(val);
        const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(val);
        const isMatch = val.length > 0 && val === confirmVal;

        // Toggle rule indicators
        if (ruleLength) ruleLength.classList.toggle('valid', hasLength);
        if (ruleUpper) ruleUpper.classList.toggle('valid', hasUpper);
        if (ruleLower) ruleLower.classList.toggle('valid', hasLower);
        if (ruleDigit) ruleDigit.classList.toggle('valid', hasDigit);
        if (ruleSpecial) ruleSpecial.classList.toggle('valid', hasSpecial);
        if (ruleMatch) ruleMatch.classList.toggle('valid', isMatch);

        // Calculate score
        let score = 0;
        if (hasLength) score += 20;
        if (val.length >= 12) score += 15;
        if (hasUpper) score += 15;
        if (hasLower) score += 15;
        if (hasDigit) score += 20;
        if (hasSpecial) score += 15;

        // Visual presentation
        if (val.length === 0) {
            strengthBar.style.width = '0%';
            strengthBar.style.backgroundColor = '#cbd5e1';
            strengthStatus.textContent = 'Too Weak';
            strengthStatus.style.color = '#ef4444';
        } else if (score < 40) {
            strengthBar.style.width = '25%';
            strengthBar.style.backgroundColor = '#ef4444'; // Red
            strengthStatus.textContent = 'Weak';
            strengthStatus.style.color = '#ef4444';
        } else if (score < 75) {
            strengthBar.style.width = '60%';
            strengthBar.style.backgroundColor = '#f59e0b'; // Amber
            strengthStatus.textContent = 'Medium';
            strengthStatus.style.color = '#f59e0b';
        } else {
            strengthBar.style.width = '100%';
            strengthBar.style.backgroundColor = '#10b981'; // Green
            strengthStatus.textContent = 'Strong & Secure';
            strengthStatus.style.color = '#10b981';
        }
    }

    passwordInput.addEventListener('input', evaluateStrength);
    if (confirmInput) {
        confirmInput.addEventListener('input', evaluateStrength);
    }
}

/**
 * Rate Limiting Countdown Timer
 */
function initLockoutCountdown() {
    const timerElem = document.getElementById('lockout-timer');
    if (!timerElem) return;

    let seconds = parseInt(timerElem.getAttribute('data-seconds'), 10) || 0;
    if (seconds <= 0) return;

    const interval = setInterval(() => {
        seconds--;
        if (seconds <= 0) {
            clearInterval(interval);
            timerElem.textContent = '0';
            // Reload page to let user retry
            window.location.reload();
        } else {
            timerElem.textContent = seconds;
        }
    }, 1000);
}

/**
 * Auto-dismiss Flash Alerts
 */
function initAlertAutoDismiss() {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        // Auto dismiss after 6 seconds if not danger/lockout
        if (!alert.classList.contains('alert-danger')) {
            setTimeout(() => {
                alert.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
                alert.style.opacity = '0';
                alert.style.transform = 'translateY(-8px)';
                setTimeout(() => alert.remove(), 400);
            }, 6000);
        }
    });
}

/**
 * Button Double-Submit Prevention & Loading Feedback
 */
function initFormSubmitFeedback() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', () => {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn && !submitBtn.disabled) {
                // Short timeout to allow browser validation first
                setTimeout(() => {
                    if (form.checkValidity()) {
                        submitBtn.classList.add('loading');
                        submitBtn.style.opacity = '0.85';
                    }
                }, 50);
            }
        });
    });
}
