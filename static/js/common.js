const $ = q => document.querySelector(q);

document.addEventListener('DOMContentLoaded', () => {
  // ава в шапке
  $('#aBtn')?.addEventListener('click', e => {
    e.stopPropagation();          
    $('#dd').classList.toggle('show');  
  });

  // закрытие нажатием в любое место
  document.addEventListener('click', () => {
    $('#dd')?.classList.remove('show');
  });

  // "Выйти"
  $('#lo')?.addEventListener('click', async e => {
    e.preventDefault();  // отменяем переход по ссылке
    // запрос на выход
    await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'include'
    });
    // публичную главную
    location.replace('/index.html');
  });
});


export async function initCommon(pageTitle = '') {
  // залогинен ли пользователь
  const r = await fetch('/api/auth/me', { credentials: 'include' });
  if (!r.ok) {
    location.replace('/');
    return null;
  }

  const me = (await r.json()).data;
  // имя в шапку
  $('#uname').textContent = me.username;

  if (pageTitle) {
    document.querySelector('.top-title').textContent = pageTitle;
  }

  // боковую панель в зависимости от роли
  renderSidebar(me.role);

  return me;
}
 
function renderSidebar(role = 'player') {
  const nav = $('#navLinks');
  nav.innerHTML = '';  

  // меню
  const items = [
    { href: '/dashboard.html', label: 'Главная' },
    { href: '/team.html',      label: 'Команда' },
    { href: '/events.html',    label: 'События' },
    { href: '/profile.html',   label: 'Профиль' }
  ];

  // админка
  if (role === 'admin') {
    items.push(
      { header: true },
      { href: '/admin_users.html', label: 'Пользователи' },
      { href: '/admin_teams.html', label: 'Команды' }
    );
  }

  // модерка
  if (role === 'admin' || role === 'moderator') {
    items.push(
      { header: true },
      { href: '/mod_create.html', label: 'Создать событие' },
      { href: '/mod_manage.html', label: 'Проведение' }
    );
  }

  // проходим по всем пунктам и вставляем их в DOM
  items.forEach(it => {
    if (it.header) {
      // пустая строка или заголовок
      nav.insertAdjacentHTML('beforeend', `<div class="nav-head"></div>`);
    } else {
      const active = location.pathname === it.href ? ' active' : '';
      nav.insertAdjacentHTML(
        'beforeend',
        `<a href="${it.href}" class="nav-link${active}">
           ${it.label}
         </a>`
      );
    }
  });
}
