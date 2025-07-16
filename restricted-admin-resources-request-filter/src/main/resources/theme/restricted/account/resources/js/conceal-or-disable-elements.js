// © 2025 Luca Filipozzi. Some rights reserved. See LICENSE.

document.addEventListener('DOMContentLoaded', function() {
  const observer = new MutationObserver(function(_) {
    modifyElements();
  });
  observer.observe(document.body, {
    childList: true,
    subtree: true
  })
});

function modifyElements() {
  try {
    concealElement(findElement('[data-testid="applications"]'));
    disableElement(findElement('[data-testid="email"]'));
    disableElement(findElement('[data-testid="firstName"]'));
    disableElement(findElement('[data-testid="lastName"]'));
    concealElement(findElement('[data-testid="save"]'));
    concealElement(findElement('[data-testid="cancel"]'));
    concealElement(findElement('[data-testid="account-security/device-activity"]'));
    concealElement(findParent('[id="two-factor-categ-title"]'));
  } catch (error) {
    console.error('error applying restrictions: ', error);
  }
}

function findElement(selector) {
  return document.querySelector(selector);
}

function findParent(selector) {
  return document.querySelector(selector)?.parentElement;
}

function concealElement(element) {
  hideElement(element);
  disableElement(element);
}

function hideElement(element) {
  if (element != null) {
    element.style.display = 'none';
    element.setAttribute('data-restricted', 'true');
  }
}

function disableElement(element) {
  if (element != null) {
    element.disabled = true;
    element.setAttribute('aria-disabled', 'true');
  }
}

