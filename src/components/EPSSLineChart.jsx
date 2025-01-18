import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
// import BulletinTypeSelector from './BulletinTypeSelector';

const EPSSLineChart = () => {
    const [data, setData] = useState([]);
    const [naCount, setNaCount] = useState(0);

    useEffect(() => {
        fetch('/fetch_data')
            .then(response => response.json())
            .then(jsonData => {
                const filteredData = jsonData.filter(item => item['Type de bulletin'] === 'Alerte');

                // Compter les N/A
                const naCounter = filteredData.filter(item => item['Score EPSS'] === 'n/a').length;

                const chartData = filteredData
                    .filter(item => item['Score EPSS'] !== 'n/a')
                    .map(item => ({
                        cve: item['Identifiant CVE'],
                        epss: parseFloat(item['Score EPSS'])
                    }))
                    .sort((a, b) => b.epss - a.epss);

                setData(chartData);
                setNaCount(naCounter);
            })
            .catch(error => console.error('Error:', error));
    }, []);

    const CustomTooltip = ({ active, payload }) => {
        if (active && payload && payload.length) {
            return (
                <div style={{
                    backgroundColor: '#242424',
                    padding: '12px',
                    border: '1px solid rgba(255,255,255,0.1)',
                    color: 'white',
                }}>
                    <div>CVE: {payload[0].payload.cve}</div>
                    <div>Score EPSS: {payload[0].value.toFixed(4)}</div>
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
                        <h2 style={{ color: 'white', fontSize: '25px', fontWeight: 'bold', marginRight: 'auto'}}>Courbe des Scores EPSS</h2>
                    </div>
                    {naCount > 0 && (
                        <div style={{
                            marginLeft: '20px',
                            textAlign: 'left',
                            marginTop: '5px',
                            fontSize: '20px',
                            fontWeight: '400',
                            color: 'rgba(255, 255, 255, 0.4)'
                        }}>
                            {naCount} vulnérabilités ne présentent pas de score EPSS
                        </div>
                    )}
                </div>
            </div>
            <ResponsiveContainer>
                <LineChart 
                    data={data}
                >
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                    <XAxis 
                        dataKey="cve" 
                        stroke="rgba(255,255,255,0.7)"
                        tick={false}
                    />
                    <YAxis 
                        stroke="rgba(255,255,255,0.7)"
                        tickFormatter={value => value.toFixed(2)}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Line 
                        type="monotone" 
                        dataKey="epss" 
                        stroke="#0a84ff" 
                        dot={false}
                    />
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
};

export default EPSSLineChart;