'use client';

import React, { useEffect, useState } from 'react';
import { cn, getScoreColor, getScoreLetter } from '@/lib/utils';

interface ScoreGaugeProps {
  score: number | null | undefined;
  letter?: string;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export default function ScoreGauge({
  score,
  letter,
  size = 'md',
  className
}: ScoreGaugeProps) {
  const displayScore = score ?? 0;
  const displayLetter = letter || getScoreLetter(displayScore);
  const color = getScoreColor(displayScore);
  
  const [offset, setOffset] = useState(0);

  const sizeMap = {
    sm: { width: 80, strokeWidth: 6, fontSizeVal: 'text-lg', fontSizeLet: 'text-xs' },
    md: { width: 140, strokeWidth: 10, fontSizeVal: 'text-3xl', fontSizeLet: 'text-sm' },
    lg: { width: 220, strokeWidth: 14, fontSizeVal: 'text-5xl', fontSizeLet: 'text-xl' }
  };

  const { width, strokeWidth, fontSizeVal, fontSizeLet } = sizeMap[size];
  const radius = (width - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;

  useEffect(() => {
    // Animación de llenado progresivo
    const progressOffset = circumference - (displayScore / 100) * circumference;
    const timer = setTimeout(() => {
      setOffset(progressOffset);
    }, 100);
    return () => clearTimeout(timer);
  }, [displayScore, circumference]);

  return (
    <div className={cn('relative flex flex-col items-center justify-center', className)}>
      <svg
        width={width}
        height={width}
        className="transform -rotate-90 transition-transform duration-500"
      >
        {/* Círculo de fondo */}
        <circle
          cx={width / 2}
          cy={width / 2}
          r={radius}
          fill="transparent"
          stroke="#1E293B"
          strokeWidth={strokeWidth}
        />
        {/* Círculo de progreso */}
        <circle
          cx={width / 2}
          cy={width / 2}
          r={radius}
          fill="transparent"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      
      {/* Texto al centro */}
      <div className="absolute flex flex-col items-center justify-center text-center">
        <span className={cn('font-extrabold tracking-tight', fontSizeVal)} style={{ color }}>
          {score != null ? `${Math.round(displayScore)}%` : '—'}
        </span>
        {score != null && (
          <span className={cn('font-semibold text-[var(--text-secondary)] mt-0.5', fontSizeLet)}>
            Clase {displayLetter}
          </span>
        )}
      </div>
    </div>
  );
}
