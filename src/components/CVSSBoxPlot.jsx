// src/components/CVSSBoxPlot.jsx
import React, { useState, useEffect } from 'react';
import { ComposedChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Line } from 'recharts';
import BulletinTypeSelector from './BulletinTypeSelector';

const CVSSBoxPlot = () => {
    const [data, setData] = useState([]);
    const [topVendors, setTopVendors] = useState(5);
    const [bulletinType, setBulletinType] = useState('all');

    useEffect(() => {
        fetch('/fetch_data')
            .then(response => response.json())
            .then(jsonData => {
                // Filtrer par type de bulletin
                const filteredData = bulletinType === 'all' 
                    ? jsonData 
                    : jsonData.filter(item => item['Type de bulletin'] === bulletinType);

                // Grouper par éditeur
                const vendorGroups = {};
                filteredData.forEach(item => {
                    const vendor = item['Éditeur'];
                    const score = parseFloat(item['Score CVSS']);
                    if (vendor !== 'n/a' && !isNaN(score)) {
                        if (!vendorGroups[vendor]) {
                            vendorGroups[vendor] = [];
                        }
                        vendorGroups[vendor].push(score);
                    }
                });

                // Calculer les statistiques pour chaque éditeur
                const boxplotData = Object.entries(vendorGroups)
                    .map(([vendor, scores]) => {
                        scores.sort((a, b) => a - b);
                        return {
                            vendor,
                            count: scores.length,
                            min: scores[0],
                            q1: scores[Math.floor(scores.length * 0.25)],
                            median: scores[Math.floor(scores.length * 0.5)],
                            q3: scores[Math.floor(scores.length * 0.75)],
                            max: scores[scores.length - 1]
                        };
                    })
                    .sort((a, b) => b.count - a.count)
                    .slice(0, topVendors);

                setData(boxplotData);
            });
    }, [topVendors, bulletinType]);

    const CustomTooltip = ({ active, payload }) => {
        if (active && payload && payload.length) {
            const stats = payload[0].payload;
            return (
                <div style={{
                    backgroundColor: '#242424',
                    padding: '12px',
                    border: '1px solid rgba(255,255,255,0.1)',
                    color: 'white',
                }}>
                    <div>Éditeur: {stats.vendor}</div>
                    <div>Maximum: {stats.max.toFixed(1)}</div>
                    <div>Q3: {stats.q3.toFixed(1)}</div>
                    <div>Médiane: {stats.median.toFixed(1)}</div>
                    <div>Q1: {stats.q1.toFixed(1)}</div>
                    <div>Minimum: {stats.min.toFixed(1)}</div>
                    <div>Nombre: {stats.count}</div>
                </div>
            );
        }
        return null;
    };

    return (
        <div>
            <div style={{ display: 'flex', flexDirection: 'row', marginTop: '10px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', marginRight: 'auto' }}>
                    <div style={{ display: 'flex', flexDirection: 'row' }}>
                        <img src="/static/icons/chart.bar.svg" style={{ opacity: '0.5', marginLeft: '20px', width: '32px', height: 'auto', marginRight: '15px' }}/>
                        <h2 style={{ color: 'white', fontSize: '25px', fontWeight: 'bold', marginRight: 'auto'}}>Distribution des Scores CVSS par Éditeur</h2>
                    </div>
                </div>
                <select
                    value={topVendors}
                    onChange={(e) => setTopVendors(Number(e.target.value))}
                    class="chart_wrapperSelectorPieChartTop"
                >
                    <option value={5}>Top 5</option>
                    <option value={10}>Top 10</option>
                    <option value={15}>Top 15</option>
                </select>
                <BulletinTypeSelector 
                    value={bulletinType} 
                    onChange={setBulletinType}
                />
            </div>
            <div>
                <ResponsiveContainer>
                    <ComposedChart
                        data={data}
                        layout="vertical"
                    >
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                        <XAxis type="number" domain={[0, 10]} stroke="rgba(255,255,255,0.7)" />
                        <YAxis 
                            dataKey="vendor" 
                            type="category" 
                            stroke="rgba(255,255,255,0.7)"
                            width={90}
                        />
                        <Tooltip content={<CustomTooltip />} />
                        {/* Boîte Q1-Q3 */}
                        <Bar dataKey="q3" stackId="a" fill="#0a84ff" />
                        <Bar dataKey="q1" stackId="a" fill="#0a84ff" />
                        {/* Lignes min-max et médiane */}
                        <Line type="monotone" dataKey="min" stroke="#ff453a" strokeWidth={2} />
                        <Line type="monotone" dataKey="max" stroke="#ff453a" strokeWidth={2} />
                        <Line type="monotone" dataKey="median" stroke="#30d158" strokeWidth={2} />
                    </ComposedChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
};

export default CVSSBoxPlot;