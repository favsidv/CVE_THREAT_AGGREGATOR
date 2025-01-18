// src/components/BulletinTypeSelector.jsx
import React from 'react';

const BulletinTypeSelector = ({ value, onChange, style = {} }) => {
    return (
        <select
            value={value}
            onChange={(e) => onChange(e.target.value)}
            class={'selector-bulletin'}
            style={{
                background: 'transparent',
                color: 'white',
                padding: '7px 20px 7px 10px',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '7px',
                outline: 'none',
                cursor: 'pointer',
                appearance: 'none',
                ...style
            }}
        >
            <option value="all">Tous les bulletins</option>
            <option value="Alerte">Alertes</option>
            <option value="Avis">Avis</option>
        </select>
    );
};

export default BulletinTypeSelector;