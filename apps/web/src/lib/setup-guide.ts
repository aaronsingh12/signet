import { useSyncExternalStore } from 'react';

const storageKey = 'signet-servicenow-setup-guide-v1';
const changeEvent = 'signet:servicenow-setup-guide-change';

function readServiceNowGuide(): boolean {
  const value = window.localStorage.getItem(storageKey);
  if (value === null || value === 'on') return true;
  if (value === 'off') return false;
  throw new Error('The saved ServiceNow Setup Guide preference is invalid; expected on or off in browser storage');
}

function subscribeServiceNowGuide(onChange: () => void): () => void {
  const onStorage = (event: StorageEvent): void => {
    if (event.storageArea === window.localStorage && (event.key === storageKey || event.key === null)) onChange();
  };
  window.addEventListener(changeEvent, onChange);
  window.addEventListener('storage', onStorage);
  return () => {
    window.removeEventListener(changeEvent, onChange);
    window.removeEventListener('storage', onStorage);
  };
}

/** Keeps ServiceNow guidance enabled by default and shares this browser's saved choice across views. */
export function useServiceNowGuideEnabled(): boolean {
  return useSyncExternalStore(subscribeServiceNowGuide, readServiceNowGuide);
}

export function saveServiceNowGuideEnabled(enabled: boolean): void {
  window.localStorage.setItem(storageKey, enabled ? 'on' : 'off');
  window.dispatchEvent(new Event(changeEvent));
}
