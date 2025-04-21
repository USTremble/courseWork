// static/js/main.js
document.addEventListener('DOMContentLoaded', () => {

    /* dropdown аватара */
    const avatarBtn  = document.getElementById('avatarBtn');
    const avatarMenu = document.getElementById('dropdownMenu');
    if (avatarBtn) {
        avatarBtn.addEventListener('click', e => {
            e.stopPropagation();
            avatarMenu.classList.toggle('show');
        });
        document.addEventListener('click', () => avatarMenu.classList.remove('show'));
    }

    /* dropdown «Выполнить действие» */
    document.querySelectorAll('.action-btn').forEach(btn => {
        const menu = btn.nextElementSibling;
        btn.addEventListener('click', e => {
            e.preventDefault(); e.stopPropagation();
            menu.classList.toggle('show-menu');
        });
    });
    document.addEventListener('click', () => {
        document.querySelectorAll('.action-menu.show-menu')
                .forEach(m => m.classList.remove('show-menu'));
    });

    /* модальные окна (Команда) */
    document.querySelectorAll('[data-modal]').forEach(btn => {
        const modal = document.getElementById(btn.dataset.modal);
        btn.addEventListener('click', () => modal.classList.add('open'));
        modal.querySelector('.close')
             .addEventListener('click', () => modal.classList.remove('open'));
    });
});
