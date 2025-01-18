class VulnerabilityTable {
    constructor() {
        this.data = [];
        this.filteredData = [];
        this.currentPage = 1;
        this.itemsPerPage = 10;
        this.sortColumn = 'date';
        this.sortDirection = 'desc';

        this.tableBody = document.getElementById('table_frameBody');
        this.searchInput = document.getElementById('table_searchContainerInput');
        this.table_paginationControlsBtnPrevPageButton = document.getElementById('table_paginationControlsBtnPrevPage');
        this.table_paginationControlsBtnNextPageButton = document.getElementById('table_paginationControlsBtnNextPage');
        this.pageInfo = document.getElementById('pageInfo');
        this.loading = document.getElementById('loading');
        this.detailModal = document.getElementById('detailModal');
        this.modalBody = document.getElementById('modalBody');
        this.modalCloseBtn = document.getElementById('modalCloseBtn');

        this.initEventListeners();
        this.fetchData();
    }

    initEventListeners() {
        // Sort functionality
        document.querySelectorAll('.table_frame th').forEach(th => {
            th.addEventListener('click', () => this.handleSort(th));
        });

        // Search functionality
        this.searchInput.addEventListener('input', () => this.handleSearch());

        // Pagination
        document.getElementById('table_paginationControlsBtnFirstPage').addEventListener('click', () => this.goToFirstPage());
        document.getElementById('table_paginationControlsBtnNextPageLastPage').addEventListener('click', () => this.goToLastPage());
        this.table_paginationControlsBtnPrevPageButton.addEventListener('click', () => this.changePage(-1));
        this.table_paginationControlsBtnNextPageButton.addEventListener('click', () => this.changePage(1));

        // Rows per page
        document.getElementById('table_paginationRowSelectorWrapperSelect').addEventListener('change', (e) => {
            this.itemsPerPage = parseInt(e.target.value);
            this.currentPage = 1;
            this.renderTable();
            this.updatePagination();
        });

        // Modal close
        this.modalCloseBtn.addEventListener('click', () => this.closeModal());
        this.detailModal.addEventListener('click', (e) => {
            if (e.target === this.detailModal) this.closeModal();
        });
    }

    async fetchData() {
        try {
            this.loading.style.display = 'flex';
            const response = await fetch('/fetch_data');
            this.data = await response.json();
            
            this.filteredData = [...this.data];
            this.sortData();
            this.renderTable();
            this.updatePagination();
        } catch (error) {
            console.error('Erreur lors du chargement des données:', error);
        } finally {
            this.loading.style.display = 'none';
        }
    }

    handleSort(th) {
        const column = th.dataset.sort;
        
        // If already sorted by this column, toggle direction
        if (this.sortColumn === column) {
            this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortColumn = column;
            this.sortDirection = 'desc';
        }

        // Reset all sort icons
        document.querySelectorAll('.table_frame th').forEach(header => {
            header.classList.remove('sorted', 'sorted-asc', 'sorted-desc');
        });

        // Add current sort classes
        th.classList.add('sorted', `sorted-${this.sortDirection}`);

        this.sortData();
        this.renderTable();
        this.updatePagination();
    }

    sortData() {
        this.filteredData.sort((a, b) => {
            let valA, valB;
            
            switch(this.sortColumn) {
                case 'cve':
                    valA = a['Identifiant CVE'] || '';
                    valB = b['Identifiant CVE'] || '';
                    break;
                case 'type':
                    valA = a['Type de bulletin'] || '';
                    valB = b['Type de bulletin'] || '';
                    break;
                case 'title':
                    valA = a['Titre du bulletin (ANSSI)'] || '';
                    valB = b['Titre du bulletin (ANSSI)'] || '';
                    break;
                case 'date':
                    valA = new Date(a['Date de publication']);
                    valB = new Date(b['Date de publication']);
                    break;
                case 'cvss':
                    valA = parseFloat(a['Score CVSS']) || -1;
                    valB = parseFloat(b['Score CVSS']) || -1;
                    break;
            }

            if (valA < valB) return this.sortDirection === 'asc' ? -1 : 1;
            if (valA > valB) return this.sortDirection === 'asc' ? 1 : -1;
            return 0;
        });
    }

    handleSearch() {
        const searchTerm = this.searchInput.value.toLowerCase();
        
        this.filteredData = this.data.filter(item => 
            item['Identifiant CVE'].toLowerCase().includes(searchTerm) ||
            item['Titre du bulletin (ANSSI)'].toLowerCase().includes(searchTerm)
        );

        this.currentPage = 1;
        this.sortData();
        this.renderTable();
        this.updatePagination();
    }

    renderTable() {
        const startIndex = (this.currentPage - 1) * this.itemsPerPage;
        const endIndex = startIndex + this.itemsPerPage;
        const pageData = this.filteredData.slice(startIndex, endIndex);

        this.tableBody.innerHTML = pageData.map(item => {
            const score = parseFloat(item['Score CVSS']);
            let severityClass = ['nan', 'N/A'];
            if (score >= 9) severityClass = ['critical', 'CRITIQUE'];
            else if (score >= 7) severityClass = ['high', 'ÉLEVÉE'];
            else if (score >= 4) severityClass = ['medium', 'MOYENNE'];
            else if (score >= 0) severityClass = ['low', 'FAIBLE'];

            return `
                <tr data-cve="${item['Identifiant CVE']}">
                    <td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;${item['Identifiant CVE']}</td>
                    <td>${item['Type de bulletin']}</td>
                    <td class="table_frameTitleWrap">${item['Titre du bulletin (ANSSI)']}<div></div></td>
                    <td>${new Date(item['Date de publication']).toLocaleDateString('fr-FR', {
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric'
                    })}</td>
                    <td>
                        <div class="table_severityBadge ${severityClass[0]}">
                            <p>${isNaN(score) ? '' : score.toFixed(1)} ${severityClass[1]}<p>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        // Add click event for row details
        this.tableBody.querySelectorAll('tr').forEach(row => {
            row.addEventListener('click', () => this.showDetails(row.dataset.cve));
        });
    }

    showDetails(cveId) {
        const vulnerability = this.data.find(item => item['Identifiant CVE'] === cveId);
        
        if (!vulnerability) return;

        const detailsToShow = [
            { label: 'CVE', value: vulnerability['Identifiant CVE'] },
            { label: 'Titre', value: vulnerability['Titre du bulletin (ANSSI)'] },
            { label: 'Type de bulletin', value: vulnerability['Type de bulletin'] },
            { label: 'Date de publication', value: new Date(vulnerability['Date de publication']).toLocaleDateString('fr-FR') },
            { label: 'Score CVSS', value: vulnerability['Score CVSS'] },
            { label: 'Sévérité', value: vulnerability['Base Severity'] },
            { label: 'Type CWE', value: vulnerability['Type CWE'] },
            { label: 'Score EPSS', value: vulnerability['Score EPSS'] },
            { label: 'Éditeur', value: vulnerability['Éditeur'] },
            { label: 'Produit', value: vulnerability['Produit'] },
            { label: 'Versions affectées', value: vulnerability['Versions affectées'] },
        ];

        this.modalBody.innerHTML = detailsToShow.map(detail => `
            <div class="detail-item">
                <div class="detail-label">${detail.label}</div>
                <div class="detail-value">${detail.value}</div>
            </div>
        `).join('');

        // Add description as full-width item
        this.modalBody.innerHTML += `
            <div style="grid-column: 1 / -1;" class="detail-item">
                <div class="detail-label">Description</div>
                <div class="detail-value">${vulnerability['Description']}</div>
            </div>
        `;

        if (vulnerability['Lien du bulletin (ANSSI)']) {
            this.modalBody.innerHTML += `
                <div style="grid-column: 1 / -1;" class="detail-item">
                    <div class="detail-label">Lien officiel</div>
                    <div class="detail-value">
                        <a href="${vulnerability['Lien du bulletin (ANSSI)']}" 
                           target="_blank" 
                           style="color: var(--primary); text-decoration: none;">
                            Voir le bulletin officiel
                        </a>
                    </div>
                </div>
            `;
        }

        this.detailModal.style.display = 'flex';
    }

    closeModal() {
        this.detailModal.style.display = 'none';
    }

    changePage(direction) {
        const totalPages = Math.ceil(this.filteredData.length / this.itemsPerPage);
        this.currentPage += direction;

        // Ensure page stays within bounds
        this.currentPage = Math.max(1, Math.min(this.currentPage, totalPages));

        this.renderTable();
        this.updatePagination();
    }

    updatePagination() {
        const totalItems = this.filteredData.length;
        const totalPages = Math.ceil(totalItems / this.itemsPerPage);
        const startItem = (this.currentPage - 1) * this.itemsPerPage + 1;
        const endItem = Math.min(startItem + this.itemsPerPage - 1, totalItems);
        
        // Update pagination controls state
        document.getElementById('table_paginationControlsBtnFirstPage').disabled = this.currentPage === 1;
        document.getElementById('table_paginationControlsBtnPrevPage').disabled = this.currentPage === 1;
        document.getElementById('table_paginationControlsBtnNextPage').disabled = this.currentPage === totalPages;
        document.getElementById('table_paginationControlsBtnNextPageLastPage').disabled = this.currentPage === totalPages;
        
        // Update page range display
        document.getElementById('table_paginationControlsRangeL').textContent = `${startItem}-${endItem}`;
        document.getElementById('table_paginationControlsRangeR').textContent = `${totalItems}`;
    }

    goToFirstPage() {
        if (this.currentPage !== 1) {
            this.currentPage = 1;
            this.renderTable();
            this.updatePagination();
        }
    }

    goToLastPage() {
        const totalPages = Math.ceil(this.filteredData.length / this.itemsPerPage);
        if (this.currentPage !== totalPages) {
            this.currentPage = totalPages;
            this.renderTable();
            this.updatePagination();
        }
    }
}

// Initialize the table when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new VulnerabilityTable();
});

window.onbeforeunload = function () {
    window.scrollTo(0, 0);
}