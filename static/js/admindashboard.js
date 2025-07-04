function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('mainContent');
    sidebar.classList.toggle('collapsed');
    mainContent.classList.toggle('expanded');
}

function showSection(section) {
    // Remove active class from all nav links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    // Add active class to clicked nav link
    event.target.classList.add('active');

    // Update header title
    const titles = {
        'dashboard': 'Dashboard Overview',
        'users': 'User Management',
        'trades': 'Trade Management',
        'stocks': 'Stock Management',
        'reports': 'Reports & Analytics',
        'settings': 'System Settings',
        'support': 'Support Center'
    };
    document.querySelector('.header-left h1').textContent = titles[section];
    console.log('Loading section:', section);
}

function showProfileMenu() {
    alert('Profile menu would be implemented here with options like:\n- Profile Settings\n- Change Password\n- Logout');
}

// Auto-refresh stats every 30 seconds
setInterval(function () {
    const statValues = document.querySelectorAll('.stat-value');
    statValues.forEach(stat => {
        const currentValue = parseInt(stat.textContent.replace(/[^0-9]/g, ''));
        const change = Math.floor(Math.random() * 10) - 5;
        const newValue = currentValue + change;

        if (stat.textContent.includes('$')) {
            stat.textContent = '$' + newValue.toLocaleString();
        } else {
            stat.textContent = newValue.toLocaleString();
        }
    });
}, 30000);

// Mobile responsiveness
function checkMobile() {
    const sidebar = document.getElementById('sidebar');
    if (window.innerWidth <= 768) {
        sidebar.classList.add('mobile-closed');
    } else {
        sidebar.classList.remove('mobile-closed');
    }
}
window.addEventListener('resize', checkMobile);
checkMobile();

// Initialize interactive features
document.addEventListener('DOMContentLoaded', function () {
    // Click handler for table rows
    document.querySelectorAll('.data-table tr').forEach(row => {
        row.addEventListener('click', function () {
            if (this.querySelector('th')) return;
            const userName = this.querySelector('td').textContent;
            console.log('Clicked on user:', userName);
        });
    });

    // Search input listener
    const searchInput = document.querySelector('.search-box input');
    searchInput.addEventListener('input', function () {
        const searchTerm = this.value.toLowerCase();
        console.log('Searching for:', searchTerm);
    });
});