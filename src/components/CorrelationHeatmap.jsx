// src/components/CorrelationHeatmap.jsx
import React, { useState, useEffect } from 'react';
import BulletinTypeSelector from './BulletinTypeSelector';

const CorrelationHeatmap = () => {
    const [data, setData] = useState([]);
    const [bulletinType, setBulletinType] = useState('all');

    const CVSS_RANGES = [
        { min: 9, max: 10, label: '9.0-10.0' },
        { min: 7, max: 8.9, label: '7.0-8.9' },
        { min: 4, max: 6.9, label: '4.0-6.9' },
        { min: 0, max: 3.9, label: '0.1-3.9' }
    ];

    const EPSS_RANGES = [
        { min: 0.75, max: 1, label: '0.75-1.00' },
        { min: 0.50, max: 0.749, label: '0.50-0.74' },
        { min: 0.25, max: 0.499, label: '0.25-0.49' },
        { min: 0, max: 0.249, label: '0.00-0.24' }
    ];

    useEffect(() => {
        fetch('/fetch_data')
            .then(response => response.json())
            .then(jsonData => {
                // Filtrer par type de bulletin
                const filteredData = bulletinType === 'all' 
                    ? jsonData 
                    : jsonData.filter(item => item['Type de bulletin'] === bulletinType);

                const heatmapData = Array(CVSS_RANGES.length).fill()
                    .map(() => Array(EPSS_RANGES.length).fill(0));

                filteredData.forEach(item => {
                    const cvss = parseFloat(item['Score CVSS']);
                    const epss = parseFloat(item['Score EPSS']);

                    if (!isNaN(cvss) && !isNaN(epss)) {
                        const cvssIndex = CVSS_RANGES.findIndex(
                            range => cvss >= range.min && cvss <= range.max
                        );
                        const epssIndex = EPSS_RANGES.findIndex(
                            range => epss >= range.min && epss <= range.max
                        );

                        if (cvssIndex !== -1 && epssIndex !== -1) {
                            heatmapData[cvssIndex][epssIndex]++;
                        }
                    }
                });

                setData(heatmapData);
            });
    }, [bulletinType]);

    const getColor = (value) => {
        const maxValue = Math.max(...data.flat());
        const intensity = Math.max(0.1, value / maxValue);
        return `rgba(10, 132, 255, ${intensity})`;
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
            <div style={{ 
                display: 'grid', 
                gridTemplateColumns: `repeat(${EPSS_RANGES.length}, 1fr)`,
                gap: '2px',
                padding: '20px',
                position: 'relative'
            }}>
                {data.map((row, i) => (
                    row.map((value, j) => (
                        <div
                            key={`${i}-${j}`}
                            style={{
                                backgroundColor: getColor(value),
                                padding: '20px',
                                position: 'relative',
                                aspectRatio: '1',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                color: 'white',
                                border: '1px solid rgba(255,255,255,0.1)',
                                fontSize: '14px'
                            }}
                            title={`CVSS: ${CVSS_RANGES[i].label}, EPSS: ${EPSS_RANGES[j].label}, Count: ${value}`}
                        >
                            {value}
                        </div>
                    ))
                ))}
                <div style={{ 
                    position: 'absolute', 
                    left: '-100px',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-around',
                    height: '100%',
                    color: 'rgba(255,255,255,0.7)'
                }}>
                    {CVSS_RANGES.map(range => (
                        <div key={range.label}>{range.label}</div>
                    ))}
                </div>
                <div style={{ 
                    position: 'absolute', 
                    top: '-30px',
                    width: '100%',
                    display: 'flex',
                    justifyContent: 'space-around',
                    color: 'rgba(255,255,255,0.7)'
                }}>
                    {EPSS_RANGES.map(range => (
                        <div key={range.label}>{range.label}</div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default CorrelationHeatmap;