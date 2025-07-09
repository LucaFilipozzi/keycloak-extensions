// © 2025 Luca Filipozzi. Some rights reserved. See LICENSE.

const originalFetch = window.fetch;
window.fetch = function(...args) {
  const [_, options] = args;
  if (options && options.headers) {
    const authorization = options.headers['Authorization'] || options.headers['authorization'];
    if (authorization && authorization.startsWith('Bearer ')) {
      window.fetch = originalFetch;
      void whoAmI(authorization);
    }
  }
  return originalFetch.apply(this, args);
};

document.addEventListener('DOMContentLoaded', function() {
  const observer = new MutationObserver(function(_) {
    if (sessionStorage.getItem('keycloak-whoami')) {
      modifyElements();
    }
  });
  observer.observe(document.body, {
    childList: true,
    subtree: true
  })
});

async function whoAmI(authorization) {
  const config = JSON.parse(document.getElementById('environment').textContent);
  const response = await fetch(`${config.consoleBaseUrl}whoami?currentRealm=${config.realm}`, {
    method: 'GET',
    credentials: 'include',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': authorization,
    }
  });
  if (response.ok) {
    sessionStorage.setItem('keycloak-whoami', btoa(JSON.stringify(await response.json())));
    modifyElements();
  }
}

function modifyElements() {
  const config = JSON.parse(document.querySelector('script[id="environment"]').textContent);
  const realmAccess = JSON.parse(atob(sessionStorage.getItem('keycloak-whoami')))['realm_access'][config.realm];
  try {
    if (document.querySelector('[data-testid="nav-item-users"]')?.getAttribute('aria-current') === 'page') {
      if (realmAccess.includes('manage-profiles') || realmAccess.includes('manage-credentials')) {
        modifyElementBySelector('[data-testid="role-mapping-tab"]', {hide: true, disable: true});
        modifyElementBySelector('[data-testid="user-groups-tab"]', {hide: true, disable: true});
        modifyElementBySelector('[data-testid="user-consents-tab"]', {hide: true, disable: true});
        modifyElementBySelector('[data-testid="identity-provider-links-tab"]', {hide: true, disable: true});
        modifyElementBySelector('[data-testid="user-sessions-tab"]', {hide: true, disable: true});
      }
      if (realmAccess.includes('manage-credentials')) {
        modifyElementBySelector('[data-testid="add-user"]', {hide: true, disable: true});
        modifyElementBySelector('[data-testid="delete-user-btn"]', {hide: true, disable: true});
        modifyElementBySelector('table[aria-label="Users"] input[name="check-all"]', {hide: true, disable: true});
        modifyElementBySelector('table[aria-label="Users"] input[name^="checkrow"]', {hide: true, disable: true});
        modifyElementBySelector('table[aria-label="Users"] button[aria-label="Kebab toggle"]', {hide: true, disable: true});
        modifyElementBySelector('[data-testid="action-dropdown"]', {hide: true, disable: true});
        modifyElementBySelector('input[id$="-switch"]', {disable: true});
        modifyElementByLabelFor('requiredActions', {disable: true});
        modifyElementByLabelFor('emailVerified', {disable: true});
        modifyElementByLabelFor('email', {disable: true});
        modifyElementByLabelFor('firstName', {disable: true});
        modifyElementByLabelFor('lastName', {disable: true});
        modifyElementByLabelFor('password-sync', {disable: true});
      }
    }
  } catch (error) {
    console.error('error applying restrictions: ', error);
  }
}

function modifyElementByLabelFor(forValue, options = {}) {
  const { hide = false, disable = false } = options;
  const formGroup = document.querySelector(`label[for="${forValue}"]`)?.parentElement?.parentElement;
  if (formGroup) {
    if (hide) {
      hideElement(formGroup);
    }
    if (disable) {
      formGroup.querySelectorAll('input, button, select, textarea').forEach(element => {
        disableElement(element);
      });
    }
  }
}

function modifyElementBySelector(selector, options = {}) {
  const { hide = false, disable = false } = options;
  document.querySelectorAll(selector).forEach(element => {
    if (hide) {
      hideElement(element);
    }
    if (disable) {
      disableElement(element);
    }
  });
}

function hideElement(element) {
  element.style.display = 'none';
  element.setAttribute('data-restricted', 'true');
}

function disableElement(element) {
  element.disabled = true;
  element.setAttribute('aria-disabled', 'true');
}
