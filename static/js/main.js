// Mobile navigation toggle
const navToggle = document.getElementById('nav-toggle');
const navList = document.getElementById('nav-list');

navToggle.addEventListener('click', () => {
    const visibility = navList.getAttribute('data-visible');
    
    if (visibility === "false") {
        navList.setAttribute('data-visible', "true");
        navToggle.setAttribute('aria-expanded', "true");
    } else {
        navList.setAttribute('data-visible', "false");
        navToggle.setAttribute('aria-expanded', "false");
    }
});

// Add scrolled class to header on scroll
window.addEventListener('scroll', () => {
    const header = document.querySelector('.main-header');
    if (window.scrollY > 50) {
        header.classList.add('scrolled');
    } else {
        header.classList.remove('scrolled');
    }
});


document.addEventListener('DOMContentLoaded', function () {
    const header = document.querySelector('.main-header');
    const hero = document.querySelector('.hero');

    // Initial check in case page loads scrolled
    if (window.scrollY > 50) {
        header.classList.add('scrolled');
    }

    window.addEventListener('scroll', function () {
        if (window.scrollY > 50) {
            header.classList.add('scrolled');
        } else {
            header.classList.remove('scrolled');
        }

        // Parallax effect
        const scrollPosition = window.scrollY;
        hero.style.backgroundPositionY = scrollPosition * 0.5 + 'px';
    });
});
// Carousel Navigation
document.addEventListener('DOMContentLoaded', function () {
    const carousel = document.querySelector('.services-carousel');
    const prevBtn = document.querySelector('.carousel-nav.prev');
    const nextBtn = document.querySelector('.carousel-nav.next');
    const indicators = document.querySelectorAll('.indicator');
    const cards = document.querySelectorAll('.service-card');
    const cardWidth = cards[0].offsetWidth + 24; // width + gap

    let currentIndex = 0;
    let autoScrollInterval;

    // Update indicators
    function updateIndicators(index) {
        indicators.forEach((indicator, i) => {
            indicator.classList.toggle('active', i === index);
        });
    }

    // Scroll to specific card
    function scrollToCard(index) {
        currentIndex = index;
        carousel.scrollTo({
            left: index * cardWidth,
            behavior: 'smooth'
        });
        updateIndicators(index);
    }

    // Navigation buttons
    prevBtn.addEventListener('click', () => {
        currentIndex = Math.max(0, currentIndex - 1);
        scrollToCard(currentIndex);
    });

    nextBtn.addEventListener('click', () => {
        currentIndex = Math.min(cards.length - 1, currentIndex + 1);
        scrollToCard(currentIndex);
    });

    // Indicator clicks
    indicators.forEach(indicator => {
        indicator.addEventListener('click', () => {
            const index = parseInt(indicator.getAttribute('data-index'));
            scrollToCard(index);
        });
    });

    // Auto-scroll (optional)
    function startAutoScroll() {
        autoScrollInterval = setInterval(() => {
            currentIndex = (currentIndex + 1) % cards.length;
            scrollToCard(currentIndex);
        }, 5000);
    }

    function stopAutoScroll() {
        clearInterval(autoScrollInterval);
    }

    // Pause auto-scroll on hover
    carousel.addEventListener('mouseenter', stopAutoScroll);
    carousel.addEventListener('mouseleave', startAutoScroll);

    // Initialize
    startAutoScroll();

    // Update indicators on scroll
    carousel.addEventListener('scroll', () => {
        const scrollPosition = carousel.scrollLeft;
        const newIndex = Math.round(scrollPosition / cardWidth);
        if (newIndex !== currentIndex) {
            currentIndex = newIndex;
            updateIndicators(currentIndex);
        }
    });
});

// Add current year automatically
document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('current-year').textContent = new Date().getFullYear();
});