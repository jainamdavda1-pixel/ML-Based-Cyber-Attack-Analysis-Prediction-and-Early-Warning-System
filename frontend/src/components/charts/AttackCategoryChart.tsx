import React from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, Cell } from 'recharts';

interface AttackCategoryChartProps {
  distribution: Record<string, number>;
}

export const AttackCategoryChart: React.FC<AttackCategoryChartProps> = ({ distribution }) => {
  const data = Object.entries(distribution)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);

  return (
    <div className="w-full h-72">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 10, right: 20, left: 10, bottom: 40 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" vertical={false} />
          <XAxis 
            dataKey="name" 
            stroke="#94A3B8" 
            fontSize={10} 
            interval={0} 
            angle={-35} 
            textAnchor="end" 
          />
          <YAxis stroke="#94A3B8" fontSize={11} />
          <Tooltip contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px' }} />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.name === 'BENIGN' ? '#10B981' : '#06B6D4'} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
