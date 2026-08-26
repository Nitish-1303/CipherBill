"use client";

import type { ReactNode } from "react";
import { motion, useReducedMotion } from "framer-motion";

import styles from "./story-chapter.module.css";

type StoryChapterProps = {
  id: string;
  index: string;
  title: string;
  thesis: string;
  icon: ReactNode;
  facts: readonly string[];
  children?: ReactNode;
  accent?: "mint" | "neutral";
};

export function StoryChapter({
  id,
  index,
  title,
  thesis,
  icon,
  facts,
  children,
  accent = "mint",
}: StoryChapterProps) {
  const reduce = useReducedMotion();

  return (
    <motion.section
      id={id}
      className={`${styles.chapter} ${accent === "neutral" ? styles.neutral : ""}`}
      initial={reduce ? false : { opacity: 0, y: 36 }}
      whileInView={reduce ? undefined : { opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.25, margin: "-10% 0px" }}
      transition={{ duration: 0.65, ease: [0.22, 1, 0.36, 1] }}
    >
      <div className={styles.meta}>
        <span className={styles.index}>{index}</span>
        <span className={styles.iconWrap}>{icon}</span>
      </div>
      <div className={styles.body}>
        <h2>{title}</h2>
        <p className={styles.thesis}>{thesis}</p>
        <ul className={styles.facts}>
          {facts.map((fact) => (
            <li key={fact}>{fact}</li>
          ))}
        </ul>
        {children ? <div className={styles.slot}>{children}</div> : null}
      </div>
    </motion.section>
  );
}
