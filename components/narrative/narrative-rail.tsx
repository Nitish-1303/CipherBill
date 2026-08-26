"use client";

import { useEffect, useState } from "react";

import {
  IconBoundary,
  IconConsole,
  IconPool,
  IconProve,
  IconSettle,
  IconShield,
} from "@/components/brand/cipherbill-icons";

import styles from "./narrative-rail.module.css";

const anchors = [
  { href: "#story", label: "Prologue", icon: IconPool },
  { href: "#shield", label: "Shield", icon: IconShield },
  { href: "#settle", label: "Settle", icon: IconSettle },
  { href: "#prove", label: "Prove", icon: IconProve },
  { href: "#demo", label: "Console", icon: IconConsole },
  { href: "#privacy", label: "Boundaries", icon: IconBoundary },
] as const;

export function NarrativeRail() {
  const [active, setActive] = useState("#story");

  useEffect(() => {
    const sections = anchors
      .map(({ href }) => document.querySelector(href))
      .filter((node): node is HTMLElement => node instanceof HTMLElement);

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        if (visible?.target.id) setActive(`#${visible.target.id}`);
      },
      { rootMargin: "-35% 0px -55% 0px", threshold: [0.15, 0.35, 0.6] },
    );

    sections.forEach((section) => observer.observe(section));
    return () => observer.disconnect();
  }, []);

  return (
    <nav className={styles.rail} aria-label="Story progress">
      <span className={styles.caption}>Story</span>
      <ol>
        {anchors.map(({ href, label, icon: Icon }) => (
          <li key={href}>
            <a className={active === href ? styles.active : undefined} href={href}>
              <Icon size={16} />
              {label}
            </a>
          </li>
        ))}
      </ol>
    </nav>
  );
}
