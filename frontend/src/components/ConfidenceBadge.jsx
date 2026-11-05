import React from 'react';
import { CheckCircle2, HelpCircle, Search, ShieldCheck } from 'lucide-react';

export const ConfidenceBadge = ({ confidence = 0.5, label, size = 'small' }) => {
  // Normalize numeric percentage
  const numScore = confidence > 1 ? confidence : Math.round(confidence * 100);

  // Derive normalized qualitative label
  let normLabel = label ? String(label).toUpperCase() : '';
  if (!normLabel) {
    if (numScore >= 90) normLabel = 'CONFIRMED';
    else if (numScore >= 75) normLabel = 'PROBABLE';
    else if (numScore >= 60) normLabel = 'SUSPECTED';
    else normLabel = 'NEEDS_VALIDATION';
  }

  const badgeConfig = {
    CONFIRMED: {
      text: 'Confirmed',
      bg: 'bg-[#cc5500]/15 text-[#cc5500] border-[#cc5500]/40',
      icon: ShieldCheck,
      dot: 'bg-[#cc5500]',
    },
    PROBABLE: {
      text: 'Probable',
      bg: 'bg-[#cc8833]/15 text-[#cc8833] border-[#cc8833]/40',
      icon: CheckCircle2,
      dot: 'bg-[#cc8833]',
    },
    SUSPECTED: {
      text: 'Suspected',
      bg: 'bg-[#c4956a]/15 text-[#c4956a] border-[#c4956a]/40',
      icon: Search,
      dot: 'bg-[#c4956a]',
    },
    NEEDS_VALIDATION: {
      text: 'Needs Validation',
      bg: 'bg-[#3b2a27] text-[#d4bfb0] border-[#6b4c45]',
      icon: HelpCircle,
      dot: 'bg-[#a08070]',
    },
  };

  const current = badgeConfig[normLabel] || badgeConfig.NEEDS_VALIDATION;
  const Icon = current.icon;

  const sizeClass =
    size === 'small'
      ? 'text-[10px] px-2 py-0.5 gap-1'
      : 'text-xs px-2.5 py-0.5 gap-1.5';

  return (
    <span
      className={`inline-flex items-center rounded font-mono font-semibold tracking-wide border ${current.bg} ${sizeClass}`}
      title={`Certainty Score: ${numScore}% — Severity indicates potential impact; Confidence indicates evidentiary certainty.`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${current.dot}`} />
      <Icon className="w-2.5 h-2.5 shrink-0" />
      <span>{current.text}</span>
      <span className="opacity-75 font-normal">({numScore}%)</span>
    </span>
  );
};
