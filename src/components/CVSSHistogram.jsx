import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import BulletinTypeSelector from './BulletinTypeSelector';

const CVSSHistogram = () => {
    const [data, setData] = useState([]);
    const [naCount, setNaCount] = useState(0);
    const [bulletinType, setBulletinType] = useState('all');

    useEffect(() => {
        fetch('/fetch_data')
            .then(response => response.json())
            .then(jsonData => {
                // Filtrer par type de bulletin
                const filteredData = bulletinType === 'all' 
                    ? jsonData 
                    : jsonData.filter(item => item['Type de bulletin'] === bulletinType);

                // Compter les N/A
                const naCounter = filteredData.filter(item => item['Score CVSS'] === 'n/a').length;

                // Préparer les données pour l'histogramme
                const scores = filteredData
                    .map(item => parseFloat(item['Score CVSS']))
                    .filter(score => !isNaN(score));

                const distribution = [
                    {
                        name: 'Critique',
                        count: scores.filter(score => score >= 9).length,
                        fill: 'rgb(104, 57, 246)'
                    },
                    {
                        name: 'Élevée',
                        count: scores.filter(score => score >= 7 && score < 9).length,
                        fill: '#ff453a'
                    },
                    {
                        name: 'Moyenne',
                        count: scores.filter(score => score >= 4 && score < 7).length,
                        fill: '#ff9f0a'
                    },
                    {
                        name: 'Faible',
                        count: scores.filter(score => score < 4).length,
                        fill: '#30d158'
                    }
                ];

                setData(distribution);
                setNaCount(naCounter);
            })
            .catch(error => console.error('Error:', error));
    }, [bulletinType]);

    const CustomTooltip = ({ active, payload, label }) => {
        if (active && payload && payload.length) {
            const total = data.reduce((sum, item) => sum + item.count, 0);
            const percentage = ((payload[0].value / total) * 100).toFixed(1);
            
            return (
                <div style={{
                    backgroundColor: '#242424',
                    padding: '12px',
                    border: '1px solid rgba(255,255,255,0.1)',
                    color: 'white',
                }}>
                    <div>{label}</div>
                    <div>Nombre: {payload[0].value}</div>
                    <div>Pourcentage: {percentage}%</div>
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
                        <h2 style={{ color: 'white', fontSize: '25px', fontWeight: 'bold', marginRight: 'auto'}}>Distribution des Scores CVSS</h2>
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
                            {naCount} vulnérabilités ne présentent pas de score CVSS
                        </div>
                    )}
                </div>
                <BulletinTypeSelector 
                    value={bulletinType} 
                    onChange={setBulletinType}
                />
            </div>
            <ResponsiveContainer>
                <BarChart
                    data={data}
                >
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.1)" />
                    <XAxis 
                        dataKey="name" 
                        stroke="rgba(255,255,255,0.7)"
                        angle={-45}
                        textAnchor="end"
                        height={80}
                    />
                    <YAxis stroke="rgba(255,255,255,0.7)" />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar dataKey="count" />
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
};

export default CVSSHistogram;