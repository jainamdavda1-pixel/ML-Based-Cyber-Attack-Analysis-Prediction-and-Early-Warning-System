import React from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, CartesianGrid } from 'recharts';

interface SHAPBarChartProps {
  data: Array<{
    feature: string;
    mean_shap_value?: number;
    importance?: number;
    description?: string;
  }>;
}

export const SHAPBarChart: React.FC<SHAPBarChartProps> = ({ data }) => {
  const formattedData = data.map(item => ({
    feature: item.feature,
    value: item.mean_shap_value !== undefined ? item.mean_shap_value : item.importance || 0,
    description: item.description || ''
  })).sort((a, b) => b.value - a.value);

  return (
    <div className="w-full h-80">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          layout="vertical"
          data={formattedData}
          margin={{ top: 5, right: 30, left: 120, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" horizontal={false} />
          <XAxis type="number" stroke="#94A3B8" fontSize={11} />
          <YAxis type="category" dataKey="feature" stroke="#94A3B8" fontSize={11} width={130} />
          <Tooltip
            contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px', color: '#F8FAFC' }}
            formatter={(val: any) => [typeof val === 'number' ? val.toFixed(4) : val, 'Contribution Magnitude']}
          />
          <Bar dataKey="value" radius={[0, 4, 4, 0]}>
            {formattedData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={index < 3 ? '#06B6D4' : '#3B82F6'} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
