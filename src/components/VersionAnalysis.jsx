// src/components/VersionAnalysis.jsx
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
                // Filtrer par type de bulletin
                const filteredData = bulletinType === 'all' 
                    ? jsonData 
                    : jsonData.filter(item => item['Type de bulletin'] === bulletinType);

                // Extraire la liste des éditeurs uniques
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
                    // Filtrer par type de bulletin
                    const filteredData = bulletinType === 'all' 
                        ? jsonData 
                        : jsonData.filter(item => item['Type de bulletin'] === bulletinType);

                    // Filtrer les produits pour l'éditeur sélectionné
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
                    // Filtrer par type de bulletin
                    const filteredData = bulletinType === 'all' 
                        ? jsonData 
                        : jsonData.filter(item => item['Type de bulletin'] === bulletinType);

                    // Analyser les versions
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

    return (
        <div style={{ width: '100%' }}>
            <div style={{
                marginBottom: '20px',
                display: 'flex',
                gap: '10px',
                alignItems: 'center',
                justifyContent: 'flex-end'
            }}>
                <BulletinTypeSelector 
                    value={bulletinType} 
                    onChange={setBulletinType}
                />
                <select
                    value={selectedVendor}
                    onChange={(e) => setSelectedVendor(e.target.value)}
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
                    {vendors.map(vendor => (
                        <option key={vendor} value={vendor}>{vendor}</option>
                    ))}
                </select>
                <select
                    value={selectedProduct}
                    onChange={(e) => setSelectedProduct(e.target.value)}
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
                    {products.map(product => (
                        <option key={product} value={product}>{product}</option>
                    ))}
                </select>
            </div>
            <div style={{ height: '400px' }}>
                <ResponsiveContainer>
                    <BarChart
                        data={data}
                        margin={{ top: 20, right: 30, left: 20, bottom: 60 }}
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
                        <Tooltip />
                        <Bar dataKey="count" fill="#ff9f0a" />
                    </BarChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
};

export default VersionAnalysis;