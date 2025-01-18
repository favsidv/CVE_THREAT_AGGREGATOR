// src/index.js
import React from 'react';
import { createRoot } from 'react-dom/client';
import CVSSHistogram from './components/CVSSHistogram';
import CWEPieChart from './components/CWEPieChart';
import EPSSLineChart from './components/EPSSLineChart';
import VendorProductChart from './components/VendorProductChart';
import CorrelationHeatmap from './components/CorrelationHeatmap';
import ScatterPlot from './components/ScatterPlot';
import CumulativeChart from './components/CumulativeChart';
import CVSSBoxPlot from './components/CVSSBoxPlot';
import CWEDetails from './components/CWEDetails';
import VersionAnalysis from './components/VersionAnalysis';

document.addEventListener('DOMContentLoaded', () => {
    // Fonction générique pour monter un composant
    const mountComponent = (id, Component) => {
        const container = document.getElementById(id);
        if (container) {
            const root = createRoot(container);
            root.render(
                <React.StrictMode>
                    <Component />
                </React.StrictMode>
            );
        } else {
            console.warn(`Container with id '${id}' not found for component ${Component.name}`);
        }
    };

    // Monter tous les composants
    const components = {
        cvssHistogram: CVSSHistogram,
        cwePieChart: CWEPieChart,
        epssLineChart: EPSSLineChart,
        vendorProductChart: VendorProductChart,
        correlationHeatmap: CorrelationHeatmap,
        scatterPlot: ScatterPlot,
        cumulativeChart: CumulativeChart,
        cvssBoxPlot: CVSSBoxPlot,
        cweDetails: CWEDetails,
        versionAnalysis: VersionAnalysis
    };

    // Monter chaque composant
    Object.entries(components).forEach(([id, Component]) => {
        mountComponent(id, Component);
    });
});