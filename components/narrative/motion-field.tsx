"use client";

import { motion, useReducedMotion } from "framer-motion";

import styles from "./motion-field.module.css";

const shards = [
  { x: "8%", y: "14%", size: 52, delay: 0, rotate: 12 },
  { x: "78%", y: "18%", size: 38, delay: 1.2, rotate: -18 },
  { x: "62%", y: "72%", size: 44, delay: 0.6, rotate: 24 },
  { x: "18%", y: "68%", size: 30, delay: 1.8, rotate: -8 },
  { x: "44%", y: "38%", size: 22, delay: 2.4, rotate: 45 },
];

export function MotionField() {
  const reduce = useReducedMotion();

  return (
    <div className={styles.field} aria-hidden="true">
      {shards.map((shard, index) => (
        <motion.span
          key={index}
          className={styles.shard}
          style={{
            left: shard.x,
            top: shard.y,
            width: shard.size,
            height: shard.size,
            rotate: shard.rotate,
          }}
          animate={
            reduce
              ? undefined
              : {
                  y: [0, -16, 0],
                  x: [0, index % 2 ? 8 : -8, 0],
                  opacity: [0.25, 0.5, 0.25],
                }
          }
          transition={{
            duration: 10 + index,
            repeat: Infinity,
            ease: "easeInOut",
            delay: shard.delay,
          }}
        />
      ))}
      <div className={styles.grid} />
    </div>
  );
}
