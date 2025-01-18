import React, { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import BulletinTypeSelector from './BulletinTypeSelector';

const COLORS = [
    '#013518', '#01561A', '#007C2E', '#019E2C', '#02B519',
    '#78DA01', '#D3E700', '#F8FF00', '#FED001', '#FDB03F',
    '#F5941D', '#F05C2A', '#ED1A23', '#B9000A', '#6F0006',
    '#FF1683', '#FF83DA', '#FEBBDA', '#BFFAFE', '#6CEBFE',
    '#3AC2FF', '#0090D8', '#0048A9', '#014383', '#014383',
    '#0048A9', '#0090D8', '#3AC2FF', '#6CEBFE', '#BFFAFE',
    '#FEBBDA', '#FF83DA', '#FF1683', '#6F0006', '#B9000A',
    '#ED1A23', '#F05C2A', '#F5941D', '#FDB03F', '#FED001',
    '#F8FF00', '#D3E700', '#78DA01', '#02B519', '#019E2C',
    '#007C2E', '#01561A'
];

const ChartPie = () => {
    const [data, setData] = useState([]);
    const [bulletinType, setBulletinType] = useState('all');
    const [displayCount, setDisplayCount] = useState(10);
    const [naCount, setNaCount] = useState(0);
    const [fullData, setFullData] = useState([]);

    useEffect(() => {
        fetch('/fetch_data')
            .then(response => response.json())
            .then(jsonData => {
                // Filtrer par type de bulletin
                const filteredData = bulletinType === 'all' 
                    ? jsonData 
                    : jsonData.filter(item => item['Type de bulletin'] === bulletinType);

                const cweCount = {};
                filteredData.forEach(item => {
                    const cwe = item['Type CWE'];
                    if (cwe !== 'n/a' && cwe) {
                        cweCount[cwe] = (cweCount[cwe] || 0) + 1;
                    }
                });

                const naCounter = filteredData.filter(item => 
                    item['Type CWE'] === 'n/a'
                    
                ).length;

                const sortedData = Object.entries(cweCount)
                    .map(([name, value]) => ({ name, value }))
                    .sort((a, b) => b.value - a.value);

                setFullData(sortedData);
                setData(sortedData.slice(0, displayCount));
                setNaCount(naCounter);
            })
            .catch(error => console.error('Error:', error));
    }, [bulletinType, displayCount]);

    useEffect(() => {
        if (displayCount === 0) {
            setData(fullData);
        } else {
            setData(fullData.slice(0, displayCount));
        }
    }, [displayCount, fullData]);

    const CustomTooltip = ({ active, payload }) => {
        if (active && payload && payload.length) {
            const total = fullData.reduce((sum, item) => sum + item.value, 0);
            const percentage = ((payload[0].value / total) * 100).toFixed(1);
            
            return (
                <div style={{
                    backgroundColor: '#242424',
                    padding: '12px',
                    border: '1px solid rgba(255,255,255,0.1)',
                    color: 'white',
                }}>
                    <div>{payload[0].name}</div>
                    <div>Occurrences: {payload[0].value}</div>
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
                        <h2 style={{ color: 'white', fontSize: '25px', fontWeight: 'bold', marginRight: 'auto'}}>Types  de  vulnérabilités CWE</h2>
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
                            {naCount} vulnérabilités ne présentent pas de CWE
                        </div>
                    )}
                </div>
                <select 
                    value={displayCount}
                    onChange={(e) => setDisplayCount(Number(e.target.value))}
                    class="chart_wrapperSelectorPieChartTop"
                >
                    <option value={0}>Tout</option>
                    <option value={50}>Top 50</option>
                    <option value={30}>Top 30</option>
                    <option value={20}>Top 20</option>
                    <option value={10}>Top 10</option>
                </select>
                <BulletinTypeSelector 
                    value={bulletinType} 
                    onChange={setBulletinType}
                />
            </div>
            <ResponsiveContainer>
                <PieChart>
                    <Pie
                        data={data}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        outerRadius={150}
                        innerRadius={50}
                        cornerRadius={data.length > 10 ? 0 : 10}
                        stroke={data.length > 10 ? 'rgba(255,255,255,0.1)' : '#242424'}
                        strokeWidth={data.length > 10 ? 2 : 5}
                    >
                        {data.map((entry, index) => (
                            <Cell
                                key={`cell-${index}`}
                                fill={COLORS[index % COLORS.length]}
                            />
                        ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                </PieChart>
            </ResponsiveContainer>
        </div>
    );
};

export default ChartPie;