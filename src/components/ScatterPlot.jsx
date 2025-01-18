// src/components/ScatterPlot.jsx
import React, { useState, useEffect } from 'react';
import { ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import BulletinTypeSelector from './BulletinTypeSelector';

const ScatterPlot = () => {
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

                const scatterData = filteredData
                    .filter(item => {
                        const cvss = parseFloat(item['Score CVSS']);
                        const epss = parseFloat(item['Score EPSS']);
                        return !isNaN(cvss) && !isNaN(epss);
                    })
                    .map(item => ({
                        cvss: parseFloat(item['Score CVSS']),
                        epss: parseFloat(item['Score EPSS']),
                        cve: item['Identifiant CVE']
                    }));

                setData(scatterData);
            });
    }, [bulletinType]);

    const CustomTooltip = ({ active, payload }) => {
        if (active && payload && payload.length) {
            const point = payload[0].payload;
            return (
                <div style={{
                    backgroundColor: '#242424',
                    padding: '12px',
                    border: '1px solid rgba(255,255,255,0.1)',
                    color: 'white',
                }}>
                    <div>CVE: {point.cve}</div>
                    <div>CVSS: {point.cvss.toFixed(2)}</div>
                    <div>EPSS: {point.epss.toFixed(4)}</div>
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
                <ScatterChart margin={{ top: 20, right: 30, bottom: 20, left: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                    <XAxis 
                        type="number" 
                        dataKey="cvss" 
                        name="CVSS" 
                        domain={[0, 10]}
                        stroke="rgba(255,255,255,0.7)"
                        label={{
                            value: 'Score CVSS',
                            position: 'bottom',
                            offset: 0,
                            style: { fill: 'rgba(255,255,255,0.7)' }
                        }}
                    />
                    <YAxis 
                        type="number" 
                        dataKey="epss" 
                        name="EPSS" 
                        domain={[0, 1]}
                        stroke="rgba(255,255,255,0.7)"
                        label={{
                            value: 'Score EPSS',
                            angle: -90,
                            position: 'left',
                            offset: 0,
                            style: { fill: 'rgba(255,255,255,0.7)' }
                        }}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Scatter 
                        name="Vulnérabilités" 
                        data={data} 
                        fill="#0a84ff"
                        fillOpacity={0.6}
                    />
                </ScatterChart>
            </ResponsiveContainer>
        </div>
    );
};

export default ScatterPlot;