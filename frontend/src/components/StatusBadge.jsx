import React from 'react';
import { Search, CheckCircle2, AlertOctagon, HelpCircle, ShieldAlert } from 'lucide-react';

export const StatusBadge = ({ status = 'new', className = '' }) => {
  const normStatus = (status || 'new').toLowerCase();

  const configs = {
    new: {
      label: 'NEW',
      bg: 'bg-[#b83a2e]/15 text-[#b83a2e] border-[#b83a2e]/40',
      icon: ShieldAlert,
      dot: 'bg-[#b83a2e]'
    },
    active: {
      label: 'NEW',
      bg: 'bg-[#b83a2e]/15 text-[#b83a2e] border-[#b83a2e]/40',
      icon: ShieldAlert,
      dot: 'bg-[#b83a2e]'
    },
    investigating: {
      label: 'INVESTIGATING',
      bg: 'bg-[#cc8833]/15 text-[#cc8833] border-[#cc8833]/40',
      icon: Search,
      dot: 'bg-[#cc8833]'
    },
    confirmed: {
      label: 'CONFIRMED',
      bg: 'bg-[#cc5500]/20 text-[#cc5500] border-[#cc5500]/50 font-bold',
      icon: AlertOctagon,
      dot: 'bg-[#cc5500]'
    },
    false_positive: {
      label: 'FALSE POSITIVE',
      bg: 'bg-[#3b2a27] text-[#a08070] border-[#6b4c45]',
      icon: HelpCircle,
      dot: 'bg-[#a08070]'
    },
    resolved: {
      label: 'RESOLVED',
      bg: 'bg-[#c4956a]/15 text-[#c4956a] border-[#c4956a]/40',
      icon: CheckCircle2,
      dot: 'bg-[#c4956a]'
    }
  };

  const current = configs[normStatus] || configs.new;
  const Icon = current.icon;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10px] font-mono uppercase tracking-wide border ${current.bg} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${current.dot} inline-block`} />
      <Icon className="w-2.5 h-2.5 shrink-0" />
      {current.label}
    </span>
  );
};

export default StatusBadge;
