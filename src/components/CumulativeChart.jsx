// src/components/CumulativeChart.jsx
import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import BulletinTypeSelector from './BulletinTypeSelector';

const CumulativeChart = () => {
    const [data, setData] = useState([]);
    const [bulletinType, setBulletinType] = useState('all');

    useEffect(() => {
        fetch('/fetch_data')
            .then(response => response.json())
            .then(jsonData => {
                // Filtrer par type de bulletin
                const filteredData = bulletinType === 'all' 
                    ? jsonData 
                    : jsonData.filter(item => item['Type de bulletin'] === bulletinType);

                // Trier les données par date
                const sortedData = filteredData
                    .map(item => ({
                        date: new Date(item['Date de publication']),
                        cve: item['Identifiant CVE']
                    }))
                    .sort((a, b) => a.date - b.date);

                // Créer la courbe cumulative
                let count = 0;
                const cumulativeData = sortedData.map(item => ({
                    date: item.date.toISOString().split('T')[0],
                    count: ++count
                }));

                setData(cumulativeData);
            });
    }, [bulletinType]);

    const CustomTooltip = ({ active, payload, label }) => {
        if (active && payload && payload.length) {
            return (
                <div style={{
                    backgroundColor: '#242424',
                    padding: '12px',
                    border: '1px solid rgba(255,255,255,0.1)',
                    color: 'white',
                }}>
                    <div>Date: {new Date(label).toLocaleDateString('fr-FR')}</div>
                    <div>Total: {payload[0].value} vulnérabilités</div>
                </div>
            );
        }
        return null;
    };

    return (
        <div style={{ width: '100%', height: '400px' }}>
            <div style={{
                marginBottom: '20px',
                display: 'flex',
                justifyContent: 'flex-end',
                gap: '10px'
            }}>
                <BulletinTypeSelector 
                    value={bulletinType} 
                    onChange={setBulletinType}
                />
            </div>
            <ResponsiveContainer>
                <LineChart
                    data={data}
                    margin={{ top: 20, right: 30, left: 20, bottom: 20 }}
                >
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                    <XAxis 
                        dataKey="date" 
                        stroke="rgba(255,255,255,0.7)"
                        tickFormatter={date => new Date(date).toLocaleDateString('fr-FR')}
                        angle={-45}
                        textAnchor="end"
                        height={80}
                    />
                    <YAxis 
                        stroke="rgba(255,255,255,0.7)"
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Line 
                        type="monotone" 
                        dataKey="count" 
                        stroke="#30d158" 
                        dot={false}
                    />
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
};

export default CumulativeChart;