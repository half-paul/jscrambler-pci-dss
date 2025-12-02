/**
 * Test Page Navigation Component
 * Provides consistent navigation across all test pages
 */

(function() {
    'use strict';

    // Detect if we need /public/ prefix based on current URL
    const needsPublicPrefix = window.location.pathname.includes('/public/');
    const pathPrefix = needsPublicPrefix ? '/public' : '';

    // Navigation configuration
    const TEST_PAGES = [
        {
            name: 'Script Integrity Test',
            url: `${pathPrefix}/test-script-integrity.html`,
            description: 'Comprehensive script integrity monitoring test suite'
        },
        {
            name: 'Auto Registration',
            url: `${pathPrefix}/test-auto-registration.html`,
            description: 'Test automatic script detection and registration'
        },
        {
            name: 'Script Blocking',
            url: `${pathPrefix}/test-script-blocking.html`,
            description: 'Test script blocking functionality in enforce mode'
        },
        {
            name: 'Dynamic Injection',
            url: `${pathPrefix}/test-dynamic-injection.html`,
            description: 'Test dynamic script injection protection'
        },
        {
            name: 'Test Variations',
            url: `${pathPrefix}/test-variations.html`,
            description: 'Test various script integrity scenarios'
        },
        {
            name: 'HTTP Header Monitor',
            url: `${pathPrefix}/test-header-monitor.html`,
            description: 'Test HTTP header tampering detection (PCI DSS 11.6.1)'
        },
        {
            name: 'Header Tampering',
            url: `${pathPrefix}/test-header-tampering.html`,
            description: 'Interactive header tampering simulation'
        },
        {
            name: 'Enter Key Support',
            url: `${pathPrefix}/test-enter-key.html`,
            description: 'Test keyboard shortcuts for authentication forms'
        }
    ];

    const ADMIN_PANEL = {
        name: 'Admin Panel',
        url: `${pathPrefix}/admin-panel.html`,
        description: 'Script approval and violation management dashboard'
    };

    /**
     * Creates and injects navigation HTML
     */
    function createNavigation() {
        const currentPage = window.location.pathname;

        const navHTML = `
            <div id="test-navigation" style="
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 12px 20px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.15);
                z-index: 9999;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            ">
                <div style="max-width: 1400px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between;">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <span style="font-weight: 600; font-size: 14px;">🧪 Test Pages</span>
                        <button id="navToggle" style="
                            background: rgba(255,255,255,0.2);
                            border: 1px solid rgba(255,255,255,0.3);
                            color: white;
                            padding: 6px 12px;
                            border-radius: 4px;
                            cursor: pointer;
                            font-size: 13px;
                            font-weight: 500;
                        ">
                            ☰ Menu
                        </button>
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <a href="${ADMIN_PANEL.url}" style="
                            background: rgba(255,255,255,0.2);
                            border: 1px solid rgba(255,255,255,0.3);
                            color: white;
                            padding: 6px 12px;
                            border-radius: 4px;
                            text-decoration: none;
                            font-size: 13px;
                            font-weight: 500;
                            transition: all 0.2s;
                        " onmouseover="this.style.background='rgba(255,255,255,0.3)'" onmouseout="this.style.background='rgba(255,255,255,0.2)'">
                            ⚙️ Admin Panel
                        </a>
                    </div>
                </div>

                <!-- Dropdown Menu -->
                <div id="navDropdown" style="
                    display: none;
                    position: absolute;
                    top: 100%;
                    left: 20px;
                    right: 20px;
                    max-width: 1400px;
                    margin: 10px auto;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 8px 24px rgba(0,0,0,0.15);
                    padding: 15px;
                    max-height: 70vh;
                    overflow-y: auto;
                ">
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 10px;">
                        ${TEST_PAGES.map(page => `
                            <a href="${page.url}" style="
                                display: block;
                                padding: 12px 15px;
                                background: ${currentPage.endsWith(page.url) ? '#f0f4ff' : '#f8f9fa'};
                                border: ${currentPage.endsWith(page.url) ? '2px solid #667eea' : '1px solid #e0e0e0'};
                                border-radius: 6px;
                                text-decoration: none;
                                color: #2c3e50;
                                transition: all 0.2s;
                            " onmouseover="if (!this.querySelector('.current-indicator')) this.style.background='#f0f4ff'; this.style.borderColor='#667eea';" onmouseout="if (!this.querySelector('.current-indicator')) { this.style.background='#f8f9fa'; this.style.borderColor='#e0e0e0'; }">
                                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 5px;">
                                    <strong style="font-size: 14px; color: #2c3e50;">${page.name}</strong>
                                    ${currentPage.endsWith(page.url) ? '<span class="current-indicator" style="background: #667eea; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600;">CURRENT</span>' : ''}
                                </div>
                                <div style="font-size: 12px; color: #7f8c8d; line-height: 1.4;">
                                    ${page.description}
                                </div>
                            </a>
                        `).join('')}
                    </div>

                    <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #e0e0e0;">
                        <a href="${ADMIN_PANEL.url}" style="
                            display: block;
                            padding: 12px 15px;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            border-radius: 6px;
                            text-decoration: none;
                            font-weight: 600;
                            text-align: center;
                            transition: transform 0.2s;
                        " onmouseover="this.style.transform='scale(1.02)'" onmouseout="this.style.transform='scale(1)'">
                            ⚙️ ${ADMIN_PANEL.name}
                            <div style="font-size: 12px; font-weight: 400; opacity: 0.9; margin-top: 3px;">
                                ${ADMIN_PANEL.description}
                            </div>
                        </a>
                    </div>
                </div>
            </div>

            <!-- Spacer to prevent content from being hidden under fixed nav -->
            <div style="height: 60px;"></div>
        `;

        // Insert navigation at the beginning of body
        document.body.insertAdjacentHTML('afterbegin', navHTML);

        // Add toggle functionality
        const toggleBtn = document.getElementById('navToggle');
        const dropdown = document.getElementById('navDropdown');
        let isOpen = false;

        toggleBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            isOpen = !isOpen;
            dropdown.style.display = isOpen ? 'block' : 'none';
            toggleBtn.textContent = isOpen ? '✕ Close' : '☰ Menu';
        });

        // Close dropdown when clicking outside
        document.addEventListener('click', function(e) {
            if (isOpen && !dropdown.contains(e.target)) {
                isOpen = false;
                dropdown.style.display = 'none';
                toggleBtn.textContent = '☰ Menu';
            }
        });

        // Prevent dropdown clicks from closing it
        dropdown.addEventListener('click', function(e) {
            e.stopPropagation();
        });

        // Close on Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && isOpen) {
                isOpen = false;
                dropdown.style.display = 'none';
                toggleBtn.textContent = '☰ Menu';
            }
        });
    }

    /**
     * Initialize navigation when DOM is ready
     */
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', createNavigation);
    } else {
        createNavigation();
    }

    //test tempering 
    
    // Expose navigation API
    window.TestNavigation = {
        pages: TEST_PAGES,
        adminPanel: ADMIN_PANEL,
        getCurrentPage: function() {
            return TEST_PAGES.find(p => window.location.pathname.endsWith(p.url));
        }
    };
})();
