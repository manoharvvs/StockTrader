// Password toggle functionality
          document.addEventListener('DOMContentLoaded', function () {
    const togglePassword = document.querySelector('.toggle-password');
          const password = document.getElementById('password');

          if (togglePassword && password) {
                    togglePassword.addEventListener('click', function () {
                              const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
                              password.setAttribute('type', type);

                              // Toggle eye icon
                              this.querySelector('i').classList.toggle('fa-eye');
                              this.querySelector('i').classList.toggle('fa-eye-slash');

                              // Accessibility update
                              const isVisible = type === 'text';
                              this.setAttribute('aria-label', isVisible ? 'Hide password' : 'Show password');
                    });
    }
});