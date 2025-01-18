// src/components/BulletinTypeSelector.jsx
import React from 'react';

const BulletinTypeSelector = ({ value, onChange }) => {
    return (
        <div style={{display:'flex'}}>
            <select
                value={value}
                onChange={(e) => onChange(e.target.value)}
                class="chart_wrapperSelectorBulletin"
            >
                <option value="all">Tous les bulletins</option>
                <option value="Alerte">Alertes</option>
                <option value="Avis">Avis</option>
            </select>
        </div>
    );
};

export default BulletinTypeSelector;