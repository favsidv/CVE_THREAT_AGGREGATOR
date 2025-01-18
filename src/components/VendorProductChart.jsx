// src/components/VendorProductChart.jsx
import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import BulletinTypeSelector from './BulletinTypeSelector';

const VendorProductChart = () => {
    const [data, setData] = useState([]);
    const [mode, setMode] = useState('vendor');
    const [bulletinType, setBulletinType] = useState('all');

    useEffect(() => {
        fetch('/fetch_data')
            .then(response => response.json())
            .then(jsonData => {
                // Filtrer par type de bulletin
                const filteredData = bulletinType === 'all' 
                    ? jsonData 
                    : jsonData.filter(item => item['Type de bulletin'] === bulletinType);

                const processData = (key) => {
                    const counts = {};
                    filteredData.forEach(item => {
                        const value = item[key === 'vendor' ? 'Éditeur' : 'Produit'];
                        if (value && value !== 'n/a') {
                            counts[value] = (counts[value] || 0) + 1;
                        }
                    });

                    return Object.entries(counts)
                        .map(([name, count]) => ({ name, count }))
                        .sort((a, b) => b.count - a.count)
                        .slice(0, 10);
                };

                setData(processData(mode));
            });
    }, [mode, bulletinType]);

    const CustomTooltip = ({ active, payload, label }) => {
        if (active && payload && payload.length) {
            return (
                <div style={{
                    backgroundColor: '#242424',
                    padding: '12px',
                    border: '1px solid rgba(255,255,255,0.1)',
                    color: 'white',
                }}>
                    <div>{label}</div>
                    <div>Vulnérabilités: {payload[0].value}</div>
                </div>
            );
        }
        return null;
    };

    return (
        <div style={{ width: '100%' }}>
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
                <select
                    value={mode}
                    onChange={(e) => setMode(e.target.value)}
                    style={{
                        background: 'transparent',
                        color: 'white',
                        padding: '7px 20px 7px 10px',
                        border: '1px solid rgba(255,255,255,0.1)',
                        borderRadius: '7px',
                        outline: 'none',
                        cursor: 'pointer'
                    }}
                >
                    <option value="vendor">Éditeurs</option>
                    <option value="product">Produits</option>
                </select>
            </div>
            <div style={{ height: '400px' }}>
                <ResponsiveContainer>
                    <BarChart
                        data={data}
                        layout="vertical"
                        margin={{ top: 20, right: 30, left: 100, bottom: 5 }}
                    >
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                        <XAxis type="number" stroke="rgba(255,255,255,0.7)" />
                        <YAxis 
                            dataKey="name" 
                            type="category" 
                            stroke="rgba(255,255,255,0.7)"
                            width={90}
                        />
                        <Tooltip content={<CustomTooltip />} />
                        <Bar dataKey="count" fill="#ff9f0a" />
                    </BarChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
};

export default VendorProductChart;