"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { useReducedMotion } from "framer-motion";
import type { Group, Mesh } from "three";

import { canRenderWebGLScene } from "@/components/narrative/scene-error-boundary";
import { HeroSceneFallback } from "@/components/narrative/hero-scene-fallback";

import styles from "./hero-scene.module.css";

function NotePlane({ radius, speed, tilt, scale }: { radius: number; speed: number; tilt: number; scale: number }) {
  const ref = useRef<Mesh>(null);

  useFrame(({ clock }) => {
    if (!ref.current) return;
    const t = clock.getElapsedTime() * speed;
    ref.current.position.x = Math.cos(t) * radius;
    ref.current.position.z = Math.sin(t) * radius;
    ref.current.position.y = Math.sin(t * 1.7) * 0.35;
    ref.current.rotation.x = tilt;
    ref.current.rotation.y = t * 0.6;
  });

  return (
    <mesh ref={ref} scale={scale}>
      <boxGeometry args={[1.35, 0.06, 0.9]} />
      <meshBasicMaterial color="#73f6bb" wireframe transparent opacity={0.55} />
    </mesh>
  );
}

function PoolCore() {
  const group = useRef<Group>(null);

  useFrame(({ clock }) => {
    if (!group.current) return;
    group.current.rotation.y = clock.getElapsedTime() * 0.12;
    group.current.rotation.x = 0.35 + Math.sin(clock.getElapsedTime() * 0.25) * 0.08;
  });

  return (
    <group ref={group}>
      <mesh>
        <icosahedronGeometry args={[1.15, 1]} />
        <meshBasicMaterial color="#21bd80" wireframe transparent opacity={0.75} />
      </mesh>
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[1.65, 0.015, 8, 64]} />
        <meshBasicMaterial color="#73f6bb" transparent opacity={0.35} />
      </mesh>
    </group>
  );
}

function SceneContents() {
  const notes = useMemo(
    () => [
      { radius: 2.2, speed: 0.35, tilt: 0.5, scale: 0.9 },
      { radius: 2.55, speed: 0.28, tilt: -0.35, scale: 1 },
      { radius: 2.85, speed: 0.22, tilt: 0.2, scale: 0.85 },
      { radius: 3.1, speed: 0.18, tilt: -0.15, scale: 0.95 },
      { radius: 2.45, speed: 0.31, tilt: 0.65, scale: 0.8 },
      { radius: 3.25, speed: 0.16, tilt: -0.5, scale: 0.75 },
    ],
    [],
  );

  return (
    <>
      <ambientLight intensity={0.35} />
      <pointLight position={[4, 6, 5]} intensity={0.8} color="#73f6bb" />
      <PoolCore />
      {notes.map((note, index) => (
        <NotePlane key={index} {...note} />
      ))}
    </>
  );
}

export function HeroScene() {
  const reduceMotion = useReducedMotion();
  const [ready, setReady] = useState(false);
  const [webgl, setWebgl] = useState(false);

  useEffect(() => {
    setReady(true);
    setWebgl(canRenderWebGLScene());
  }, []);

  if (!ready || reduceMotion || !webgl) {
    return <HeroSceneFallback />;
  }

  return (
    <div className={styles.wrap} aria-hidden="true">
      <Canvas camera={{ position: [0, 1.4, 5.8], fov: 42 }} dpr={[1, 1.5]} gl={{ alpha: true, antialias: true, powerPreference: "low-power" }}>
        <SceneContents />
      </Canvas>
      <div className={styles.glow} />
    </div>
  );
}
