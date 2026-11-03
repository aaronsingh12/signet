// The seal mark: a ring with a tick, gold on navy.
export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <circle cx="16" cy="16" r="14" fill="none" stroke="#E2B53E" strokeWidth="2.5" strokeDasharray="4 2.2" />
      <circle cx="16" cy="16" r="9.5" fill="#E2B53E" />
      <path d="M11.5 16.3l3 3 6-6.3" fill="none" stroke="#0B1220" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
