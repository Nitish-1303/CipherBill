import styles from "./hero-scene.module.css";

export function HeroSceneFallback() {
  return (
    <div className={styles.wrap} aria-hidden="true">
      <svg className={styles.fallback} viewBox="0 0 320 320" aria-hidden="true">
        <circle cx="160" cy="160" r="118" stroke="#21bd80" strokeWidth="1" opacity="0.35" fill="none" />
        <circle cx="160" cy="160" r="88" stroke="#73f6bb" strokeWidth="1" opacity="0.55" fill="none" strokeDasharray="6 10" />
        <polygon
          points="160,92 210,150 160,208 110,150"
          stroke="#73f6bb"
          strokeWidth="1.2"
          fill="none"
          opacity="0.7"
        />
        <rect x="118" y="132" width="34" height="22" rx="3" stroke="#73f6bb" strokeWidth="1.2" fill="none" opacity="0.65" />
        <rect x="168" y="118" width="34" height="22" rx="3" stroke="#73f6bb" strokeWidth="1.2" fill="none" opacity="0.45" />
        <rect x="188" y="178" width="34" height="22" rx="3" stroke="#73f6bb" strokeWidth="1.2" fill="none" opacity="0.55" />
      </svg>
    </div>
  );
}
