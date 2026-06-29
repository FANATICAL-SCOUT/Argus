/* pscan Dashboard — app.js */
(function () {
  'use strict';

  const sidebar    = document.getElementById('sidebar');
  const wrapper    = document.getElementById('mainWrapper');
  const toggleBtn  = document.getElementById('sidebarToggle');       // sidebar hamburger (desktop)
  const mobileBtn  = document.getElementById('sidebarToggleMobile'); // topbar hamburger (mobile)

  // ── Persist sidebar state ──────────────────────────────────────────
  const COLLAPSED_KEY = 'pscan_sidebar_collapsed';
  const MOBILE_BP = 768;

  function isMobile() {
    return window.innerWidth <= MOBILE_BP;
  }

  function applySidebarState() {
    if (!sidebar || !wrapper) return;
    if (isMobile()) {
      sidebar.classList.remove('collapsed');
      wrapper.classList.remove('sidebar-collapsed');
    } else {
      const collapsed = localStorage.getItem(COLLAPSED_KEY) === '1';
      sidebar.classList.toggle('collapsed', collapsed);
      wrapper.classList.toggle('sidebar-collapsed', collapsed);
    }
  }

  const backdrop = document.getElementById('sidebarBackdrop');

  function closeMobileSidebar() {
    sidebar && sidebar.classList.remove('mobile-open');
    backdrop && (backdrop.style.display = 'none');
  }

  function openMobileSidebar() {
    sidebar && sidebar.classList.add('mobile-open');
    backdrop && (backdrop.style.display = 'block');
  }

  // Desktop sidebar hamburger — collapses/expands the sidebar
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      const nowCollapsed = !sidebar.classList.contains('collapsed');
      sidebar.classList.toggle('collapsed', nowCollapsed);
      wrapper.classList.toggle('sidebar-collapsed', nowCollapsed);
      localStorage.setItem(COLLAPSED_KEY, nowCollapsed ? '1' : '0');
    });
  }

  // Mobile topbar hamburger — opens/closes the slide-in sidebar
  if (mobileBtn) {
    mobileBtn.addEventListener('click', () => {
      sidebar.classList.contains('mobile-open') ? closeMobileSidebar() : openMobileSidebar();
    });
  }

  // Close sidebar on mobile when clicking backdrop or outside
  backdrop && backdrop.addEventListener('click', closeMobileSidebar);
  document.addEventListener('click', (e) => {
    if (!isMobile()) return;
    if (sidebar && sidebar.classList.contains('mobile-open')) {
      const clickedMobileBtn = mobileBtn && (e.target === mobileBtn || mobileBtn.contains(e.target));
      if (!sidebar.contains(e.target) && !clickedMobileBtn) {
        closeMobileSidebar();
      }
    }
  });

  window.addEventListener('resize', applySidebarState);
  applySidebarState();

  // ── Auto-show toasts ───────────────────────────────────────────────
  document.querySelectorAll('.toast').forEach((el) => {
    if (typeof bootstrap !== 'undefined') {
      const t = bootstrap.Toast.getOrCreateInstance(el);
      t.show();
    }
  });

  // ── Relative time labels ───────────────────────────────────────────
  function relativeTime(isoStr) {
    try {
      const diff = Math.round((Date.now() - new Date(isoStr).getTime()) / 1000);
      if (diff < 60) return diff + 's ago';
      if (diff < 3600) return Math.round(diff / 60) + 'm ago';
      if (diff < 86400) return Math.round(diff / 3600) + 'h ago';
      return Math.round(diff / 86400) + 'd ago';
    } catch (_) {
      return '';
    }
  }

  document.querySelectorAll('[data-rel-time]').forEach((el) => {
    const rel = relativeTime(el.dataset.relTime);
    if (rel) el.title = el.textContent;
    if (rel) el.textContent = rel;
  });

})();
