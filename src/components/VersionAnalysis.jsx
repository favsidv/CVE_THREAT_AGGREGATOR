import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import BulletinTypeSelector from './BulletinTypeSelector';

const VersionAnalysis = () => {
    const [data, setData] = useState([]);
    const [selectedVendor, setSelectedVendor] = useState('');
    const [selectedProduct, setSelectedProduct] = useState('');
    const [vendors, setVendors] = useState([]);
    const [products, setProducts] = useState([]);
    const [bulletinType, setBulletinType] = useState('all');

    useEffect(() => {
        fetch('/fetch_data')
            .then(response => response.json())
            .then(jsonData => {
                const filteredData = bulletinType === 'all' 
                    ? jsonData 
                    : jsonData.filter(item => item['Type de bulletin'] === bulletinType);

                const uniqueVendors = [...new Set(filteredData
                    .map(item => item['Éditeur'])
                    .filter(v => v !== 'n/a')
                )];
                setVendors(uniqueVendors);
                if (uniqueVendors.length > 0 && !selectedVendor) {
                    setSelectedVendor(uniqueVendors[0]);
                }
            });
    }, [bulletinType]);

    useEffect(() => {
        if (selectedVendor) {
            fetch('/fetch_data')
                .then(response => response.json())
                .then(jsonData => {
                    const filteredData = bulletinType === 'all' 
                        ? jsonData 
                        : jsonData.filter(item => item['Type de bulletin'] === bulletinType);

                    const uniqueProducts = [...new Set(filteredData
                        .filter(item => item['Éditeur'] === selectedVendor)
                        .map(item => item['Produit'])
                        .filter(p => p !== 'n/a')
                    )];
                    setProducts(uniqueProducts);
                    if (uniqueProducts.length > 0) {
                        setSelectedProduct(uniqueProducts[0]);
                    }
                });
        }
    }, [selectedVendor, bulletinType]);

    useEffect(() => {
        if (selectedVendor && selectedProduct) {
            fetch('/fetch_data')
                .then(response => response.json())
                .then(jsonData => {
                    const filteredData = bulletinType === 'all' 
                        ? jsonData 
                        : jsonData.filter(item => item['Type de bulletin'] === bulletinType);

                    const versionData = new Map();
                    filteredData
                        .filter(item => 
                            item['Éditeur'] === selectedVendor && 
                            item['Produit'] === selectedProduct
                        )
                        .forEach(item => {
                            const versions = item['Versions affectées']
                                .split(',')
                                .map(v => v.trim())
                                .filter(v => v !== 'n/a' && v !== '');
                            
                            versions.forEach(version => {
                                versionData.set(version, (versionData.get(version) || 0) + 1);
                            });
                        });

                    const chartData = Array.from(versionData.entries())
                        .map(([version, count]) => ({
                            version,
                            count
                        }))
                        .sort((a, b) => b.count - a.count)
                        .slice(0, 10);

                    setData(chartData);
                });
        }
    }, [selectedVendor, selectedProduct, bulletinType]);

    const CustomTooltip = ({ active, payload }) => {
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
                    <div>Version: {payload[0].payload.version}</div>
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
                        <h2 style={{ color: 'white', fontSize: '25px', fontWeight: 'bold', marginRight: 'auto'}}>Analyse des Versions Affectées</h2>
                    </div>
                </div>
                <select
                    value={selectedVendor}
                    onChange={(e) => setSelectedVendor(e.target.value)}
                    className="chart_wrapperSelectorPieChartTop"
                >
                    {vendors.map(vendor => (
                        <option key={vendor} value={vendor}>{vendor}</option>
                    ))}
                </select>
                <select
                    value={selectedProduct}
                    onChange={(e) => setSelectedProduct(e.target.value)}
                    className="chart_wrapperSelectorPieChartTop"
                >
                    {products.map(product => (
                        <option key={product} value={product}>{product}</option>
                    ))}
                </select>
                <BulletinTypeSelector 
                    value={bulletinType} 
                    onChange={setBulletinType}
                />
            </div>
            <div>
                <ResponsiveContainer>
                    <BarChart
                        data={data}
                        margin={{ bottom: 30 }}
                    >
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                        <XAxis 
                            dataKey="version"
                            stroke="rgba(255,255,255,0.7)"
                            angle={-45}
                            textAnchor="end"
                            height={80}
                        />
                        <YAxis stroke="rgba(255,255,255,0.7)" />
                        <Tooltip content={<CustomTooltip />} />
                        <Bar dataKey="count" fill="#ff9f0a" />
                    </BarChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
};

export default VersionAnalysis;