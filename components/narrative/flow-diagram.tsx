"use client";

import { useState } from "react";

import styles from "./flow-diagram.module.css";

const nodes = [
  { id: "shield", label: "Shield", x: 80, y: 120 },
  { id: "pool", label: "STRK20 pool", x: 220, y: 120 },
  { id: "settle", label: "Settle", x: 360, y: 120 },
  { id: "prove", label: "Prove", x: 500, y: 120 },
] as const;

type FlowStep = (typeof nodes)[number]["id"];

export function FlowDiagram() {
  const [active, setActive] = useState<FlowStep>("shield");

  return (
    <div className={styles.wrap}>
      <div className={styles.controls} role="tablist" aria-label="Payment flow steps">
        {nodes.map((node) => (
          <button
            key={node.id}
            type="button"
            role="tab"
            aria-selected={active === node.id}
            className={active === node.id ? styles.controlActive : undefined}
            onClick={() => setActive(node.id)}
          >
            {node.label}
          </button>
        ))}
      </div>
      <svg className={styles.svg} viewBox="0 0 580 220" aria-hidden="true">
        <defs>
          <linearGradient id="flow-line" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#21bd80" stopOpacity="0.2" />
            <stop offset="100%" stopColor="#73f6bb" stopOpacity="0.85" />
          </linearGradient>
        </defs>
        <path
          d="M80 120 H500"
          stroke="url(#flow-line)"
          strokeWidth="2"
          strokeDasharray="6 8"
          fill="none"
          opacity="0.55"
        />
        {nodes.map((node) => (
          <g key={node.id} transform={`translate(${node.x}, ${node.y})`}>
            <circle
              r={active === node.id ? 22 : 16}
              fill={active === node.id ? "rgba(115,246,187,0.18)" : "rgba(255,255,255,0.04)"}
              stroke={active === node.id ? "#73f6bb" : "#21302b"}
              strokeWidth="1.5"
            />
            <text y="44" textAnchor="middle" className={styles.nodeLabel}>
              {node.label}
            </text>
          </g>
        ))}
        <g
          className={styles.flowDotGroup}
          transform={`translate(${(nodes.find((node) => node.id === active)?.x ?? 80) - 7}, 113)`}
        >
          <circle r="7" fill="#73f6bb" />
        </g>
      </svg>
      <p className={styles.copy}>
        {active === "shield"
          ? "Public STRK enters the pool through a wallet-signed deposit. Amount and address are visible on-chain at this edge."
          : active === "pool"
            ? "Inside the pool, notes are encrypted. Sender, recipient, and in-pool amounts are not published."
            : active === "settle"
              ? "Recipients receive shielded value without exposing the payer's balance history to observers."
              : "Auditors can receive selective proofs—only the fields you choose to disclose."}
      </p>
    </div>
  );
}
