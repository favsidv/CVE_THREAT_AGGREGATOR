// src/components/CWEDetails.jsx
import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line } from 'recharts';
import BulletinTypeSelector from './BulletinTypeSelector';

const COLORS = ['#ff453a', '#ff9f0a', '#0a84ff', '#30d158', '#bf5af2', '#64d2ff'];

const CWEDetails = () => {
    const [data, setData] = useState([]);
    const [selectedCWE, setSelectedCWE] = useState('');
    const [cweList, setCWEList] = useState([]);
    const [cweStats, setCWEStats] = useState(null);
    const [bulletinType, setBulletinType] = useState('all');

    useEffect(() => {
        fetch('/fetch_data')
            .then(response => response.json())
            .then(jsonData => {
                // Filtrer par type de bulletin
                const filteredData = bulletinType === 'all' 
                    ? jsonData 
                    : jsonData.filter(item => item['Type de bulletin'] === bulletinType);

                // Extraire la liste unique des CWE
                const uniqueCWE = [...new Set(filteredData
                    .map(item => item['Type CWE'])
                    .filter(cwe => cwe !== 'n/a')
                )];
                setCWEList(uniqueCWE);
                if (uniqueCWE.length > 0 && !selectedCWE) {
                    setSelectedCWE(uniqueCWE[0]);
                }
            });
    }, [bulletinType]);

    useEffect(() => {
        if (selectedCWE) {
            fetch('/fetch_data')
                .then(response => response.json())
                .then(jsonData => {
                    // Filtrer par type de bulletin
                    const filteredData = bulletinType === 'all' 
                        ? jsonData 
                        : jsonData.filter(item => item['Type de bulletin'] === bulletinType);

                    const cweData = filteredData.filter(item => item['Type CWE'] === selectedCWE);

                    // Statistiques CVSS
                    const cvssScores = cweData
                        .map(item => parseFloat(item['Score CVSS']))
                        .filter(score => !isNaN(score));

                    // Distribution par éditeur
                    const vendorDist = {};
                    cweData.forEach(item => {
                        const vendor = item['Éditeur'];
                        if (vendor !== 'n/a') {
                            vendorDist[vendor] = (vendorDist[vendor] || 0) + 1;
                        }
                    });

                    // Type de bulletin
                    const bulletinTypes = {};
                    cweData.forEach(item => {
                        const type = item['Type de bulletin'];
                        bulletinTypes[type] = (bulletinTypes[type] || 0) + 1;
                    });

                    // Timeline
                    const timelineData = new Map();
                    cweData.forEach(item => {
                        const date = item['Date de publication'].split('T')[0];
                        timelineData.set(date, (timelineData.get(date) || 0) + 1);
                    });

                    const timeline = Array.from(timelineData.entries())
                        .map(([date, count]) => ({ date, count }))
                        .sort((a, b) => new Date(a.date) - new Date(b.date));

                    setCWEStats({
                        count: cweData.length,
                        avgCVSS: cvssScores.length ? cvssScores.reduce((a, b) => a + b, 0) / cvssScores.length : 0,
                        maxCVSS: cvssScores.length ? Math.max(...cvssScores) : 0,
                        minCVSS: cvssScores.length ? Math.min(...cvssScores) : 0,
                        vendorDistribution: Object.entries(vendorDist)
                            .map(([name, value]) => ({ name, value }))
                            .sort((a, b) => b.value - a.value),
                        bulletinDistribution: Object.entries(bulletinTypes)
                            .map(([name, value]) => ({ name, value })),
                        timeline: timeline
                    });
                });
        }
    }, [selectedCWE, bulletinType]);

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
                    <div>Nombre: {payload[0].value}</div>
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
                justifyContent: 'space-between',
                alignItems: 'center'
            }}>
                <select
                    value={selectedCWE}
                    onChange={(e) => setSelectedCWE(e.target.value)}
                    style={{
                        background: 'blue',
                        color: 'white',
                        padding: '7px 20px 7px 10px',
                        border: '1px solid rgba(255,255,255,0.1)',
                        borderRadius: '7px',
                        outline: 'none',
                        cursor: 'pointer',
                        width: '400px'
                    }}
                >
                    {cweList.map(cwe => (
                        <option key={cwe} value={cwe}>{cwe}</option>
                    ))}
                </select>
                <BulletinTypeSelector 
                    value={bulletinType} 
                    onChange={setBulletinType}
                />
            </div>

            {cweStats && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                    {/* ... le reste du contenu reste identique ... */}
                </div>
            )}
        </div>
    );
};

export default CWEDetails;