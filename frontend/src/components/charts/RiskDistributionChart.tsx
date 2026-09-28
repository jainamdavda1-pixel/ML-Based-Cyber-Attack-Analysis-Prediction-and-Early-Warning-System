import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend } from 'recharts';

interface RiskDistributionChartProps {
  distribution: Record<string, number>;
}

export const RiskDistributionChart: React.FC<RiskDistributionChartProps> = ({ distribution }) => {
  const data = [
    { name: 'Low (0-30)', value: distribution['Low'] || 0, color: '#10B981' },
    { name: 'Moderate (30-60)', value: distribution['Moderate'] || 0, color: '#F59E0B' },
    { name: 'High (60-80)', value: distribution['High'] || 0, color: '#F97316' },
    { name: 'Critical (80-100)', value: distribution['Critical'] || 0, color: '#EF4444' },
  ].filter(d => d.value >= 0);

  return (
    <div className="w-full h-64">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={80}
            paddingAngle={4}
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px' }} />
          <Legend verticalAlign="bottom" height={36} formatter={(val) => <span className="text-xs text-slate-300 font-mono">{val}</span>} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};
