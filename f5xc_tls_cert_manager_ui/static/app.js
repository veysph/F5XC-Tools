// F5 Distributed Cloud TLS Certificate Manager JavaScript

class CertificateManager {
    constructor() {
        this.certificates = [];
        this.currentCertificate = null;
        this.settings = null;
        this.trackingData = null;
        this.currentFilter = null;
        this.init();
    }

    init() {
        this.loadSettings();
        this.loadTrackingData();
        this.loadCertificates();
    }

    async loadTrackingData() {
        try {
            const response = await fetch('/api/tracking');
            this.trackingData = await response.json();
        } catch (error) {
            console.error('Error loading tracking data:', error);
            this.trackingData = { certificates: {}, history: [] };
        }
    }

    async loadSettings() {
        try {
            const response = await fetch('/api/settings');
            this.settings = await response.json();
        } catch (error) {
            console.error('Error loading settings:', error);
            this.settings = {
                tenant_name: '',
                namespace: '',
                client_cert_path: '',
                has_password: false
            };
        }
    }

    async loadCertificates() {
        try {
            this.showLoading();
            const response = await fetch('/api/certificates');
            const certificates = await response.json();
            
            this.certificates = certificates;
            this.renderExpiryDashboard();
            this.renderCertificates();
            this.hideLoading();
        } catch (error) {
            console.error('Error loading certificates:', error);
            this.showAlert('Error loading certificates: ' + error.message, 'danger');
            this.hideLoading();
        }
    }

    renderCertificates() {
        const container = document.getElementById('certificates-container');
        const emptyState = document.getElementById('empty-state');

        // Apply current filter
        let certificatesToShow = this.certificates;
        if (this.currentFilter) {
            certificatesToShow = this.certificates.filter(cert => {
                return this.getExpiryStatus(cert) === this.currentFilter;
            });
        }

        if (certificatesToShow.length === 0) {
            container.style.display = 'none';
            emptyState.style.display = 'block';
            
            // Update empty state message based on filter
            const emptyStateIcon = emptyState.querySelector('i');
            const emptyStateTitle = emptyState.querySelector('h3');
            const emptyStateText = emptyState.querySelector('p');
            
            if (this.currentFilter) {
                emptyStateIcon.className = 'fas fa-filter fa-3x text-muted mb-3';
                emptyStateTitle.textContent = `No ${this.currentFilter} certificates`;
                emptyStateText.innerHTML = `
                    No certificates found with '${this.currentFilter}' status.
                    <br><button class="btn btn-link p-0" onclick="certificateManager.clearFilter()">Show all certificates</button>
                `;
            } else if (this.certificates.length === 0) {
                emptyStateIcon.className = 'fas fa-certificate fa-3x text-muted mb-3';
                emptyStateTitle.textContent = 'No certificates found';
                emptyStateText.textContent = 'No Let\'s Encrypt certificates were found in the certs directory.';
            }
            return;
        }

        emptyState.style.display = 'none';
        container.style.display = 'block';
        container.innerHTML = '';

        // Sort certificates by expiry urgency
        const sortedCerts = certificatesToShow.sort((a, b) => {
            const statusOrder = { expired: 0, critical: 1, urgent: 2, attention: 3, safe: 4 };
            const statusA = this.getExpiryStatus(a);
            const statusB = this.getExpiryStatus(b);
            
            if (statusOrder[statusA] !== statusOrder[statusB]) {
                return statusOrder[statusA] - statusOrder[statusB];
            }
            
            // If same status, sort by days remaining
            return a.days_until_expiry - b.days_until_expiry;
        });

        sortedCerts.forEach(cert => {
            const card = this.createCertificateCard(cert);
            container.appendChild(card);
        });

        // Update page title with filter info
        this.updatePageTitle(certificatesToShow.length);
    }

    filterByStatus(status) {
        this.currentFilter = status;
        this.renderCertificates();
        
        // Scroll to certificates section
        document.getElementById('certificates-container').scrollIntoView({ behavior: 'smooth' });
        
        // Show filter indicator
        this.showAlert(`Filtered to show only '${status}' certificates. Click any stat to filter or refresh to show all.`, 'info');
    }

    clearFilter() {
        this.currentFilter = null;
        this.renderCertificates();
        this.showAlert('Filter cleared - showing all certificates', 'info');
    }

    showCheckF5XCModal(directoryName) {
        // Set the certificate name in the modal
        document.getElementById('check-cert-name').textContent = directoryName;
        
        // Pre-fill with default namespace from settings
        const namespaceInput = document.getElementById('check-namespace');
        namespaceInput.value = this.settings?.namespace || '';
        
        // Store the directory name for later use
        this.currentCheckDirectory = directoryName;
        
        // Show the modal
        const modal = new bootstrap.Modal(document.getElementById('checkF5XCModal'));
        modal.show();
    }

    async executeF5XCCheck() {
        const namespace = document.getElementById('check-namespace').value.trim();
        
        if (!namespace) {
            this.showAlert('Please specify a namespace to search', 'warning');
            return;
        }
        
        if (!this.currentCheckDirectory) {
            this.showAlert('No certificate selected', 'danger');
            return;
        }
        
        // Hide the modal
        const modal = bootstrap.Modal.getInstance(document.getElementById('checkF5XCModal'));
        modal.hide();
        
        // Show loading state
        this.showAlert('Checking F5XC for matching certificates...', 'info');
        
        try {
            // Get current settings for the request
            const settings = await this.getCurrentSettings();
            
            const response = await fetch('/api/f5xc/check', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    directory_name: this.currentCheckDirectory,
                    namespace: namespace,
                    settings: settings
                })
            });
            
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.error || 'Failed to check F5XC certificate');
            }
            
            if (result.found) {
                const cert = result.certificate;
                const timestamps = cert.timestamps || {};
                const certInfo = cert.cert_info || {};
                const matchedDomains = cert.matched_domains || [];
                
                let timestampInfo = '';
                if (timestamps.creation_timestamp) {
                    const createdDate = new Date(timestamps.creation_timestamp).toLocaleDateString();
                    timestampInfo += `<strong>Created:</strong> ${createdDate}<br>`;
                }
                if (timestamps.modification_timestamp && timestamps.modification_timestamp !== timestamps.creation_timestamp) {
                    const modifiedDate = new Date(timestamps.modification_timestamp).toLocaleDateString();
                    timestampInfo += `<strong>Modified:</strong> ${modifiedDate}<br>`;
                }
                
                let certInfoDetails = '';
                if (certInfo.expiry) {
                    const expiryDate = new Date(certInfo.expiry).toLocaleDateString();
                    certInfoDetails += `<strong>Expires:</strong> ${expiryDate}<br>`;
                }
                if (certInfo.issuer) {
                    certInfoDetails += `<strong>Issuer:</strong> ${certInfo.issuer}<br>`;
                }
                if (certInfo.public_key_algorithm) {
                    certInfoDetails += `<strong>Algorithm:</strong> ${certInfo.public_key_algorithm}<br>`;
                }
                
                let matchInfo = '';
                if (matchedDomains.length > 0) {
                    matchInfo = `<strong>Matched:</strong> `;
                    const matches = matchedDomains.map(match => {
                        const [local, remote, type] = match;
                        return `${local} ↔ ${remote} (${type})`;
                    });
                    matchInfo += matches.join(', ') + '<br>';
                }
                
                this.showAlert(
                    `✅ Certificate found in F5XC!<br>` +
                    `<strong>Name:</strong> ${cert.name}<br>` +
                    `<strong>Namespace:</strong> ${cert.namespace}<br>` +
                    `<strong>F5XC Domains:</strong> ${cert.domains.join(', ')}<br>` +
                    `<strong>Local Domains:</strong> ${result.local_domains.join(', ')}<br>` +
                    matchInfo +
                    certInfoDetails +
                    timestampInfo +
                    `Local tracking has been updated with F5XC information.`,
                    'success'
                );
                
                // Refresh certificates to show updated tracking
                await this.loadTrackingData();
                this.loadCertificates();
            } else {
                this.showAlert(
                    `ℹ️ No matching certificate found in F5XC namespace '${namespace}'<br>` +
                    `<strong>Local domains checked:</strong> ${result.local_domains.join(', ')}<br>` +
                    `You may need to create this certificate on F5XC.`,
                    'info'
                );
            }
            
        } catch (error) {
            console.error('Error checking F5XC certificate:', error);
            this.showAlert('Error checking F5XC certificate: ' + error.message, 'danger');
        } finally {
            // Clear the current check directory
            this.currentCheckDirectory = null;
        }
    }

    updatePageTitle(count) {
        const title = this.currentFilter 
            ? `${count} ${this.currentFilter} certificate${count !== 1 ? 's' : ''}`
            : `${count} certificate${count !== 1 ? 's' : ''}`;
        
        // You could update a page element here if desired
        console.log(`Displaying: ${title}`);
    }

    renderExpiryDashboard() {
        const dashboard = document.getElementById('expiry-dashboard');
        const statsContainer = document.getElementById('expiry-stats');
        
        if (this.certificates.length === 0) {
            dashboard.style.display = 'none';
            return;
        }

        // Calculate expiry statistics
        const stats = {
            expired: 0,
            critical: 0,
            urgent: 0,
            attention: 0,
            safe: 0,
            total: this.certificates.length
        };

        this.certificates.forEach(cert => {
            const status = this.getExpiryStatus(cert);
            stats[status]++;
        });

        // Generate stats HTML
        const statsHtml = `
            <div class="expiry-stat stat-expired" onclick="certificateManager.filterByStatus('expired')">
                <div class="expiry-stat-number">${stats.expired}</div>
                <div class="expiry-stat-label">Expired</div>
                <div class="expiry-stat-sublabel">Immediate action required</div>
            </div>
            <div class="expiry-stat stat-critical" onclick="certificateManager.filterByStatus('critical')">
                <div class="expiry-stat-number">${stats.critical}</div>
                <div class="expiry-stat-label">Critical</div>
                <div class="expiry-stat-sublabel">≤ 7 days remaining</div>
            </div>
            <div class="expiry-stat stat-urgent" onclick="certificateManager.filterByStatus('urgent')">
                <div class="expiry-stat-number">${stats.urgent}</div>
                <div class="expiry-stat-label">Urgent</div>
                <div class="expiry-stat-sublabel">≤ 14 days remaining</div>
            </div>
            <div class="expiry-stat stat-attention" onclick="certificateManager.filterByStatus('attention')">
                <div class="expiry-stat-number">${stats.attention}</div>
                <div class="expiry-stat-label">Attention</div>
                <div class="expiry-stat-sublabel">≤ 30 days remaining</div>
            </div>
            <div class="expiry-stat stat-safe" onclick="certificateManager.filterByStatus('safe')">
                <div class="expiry-stat-number">${stats.safe}</div>
                <div class="expiry-stat-label">Safe</div>
                <div class="expiry-stat-sublabel">> 30 days remaining</div>
            </div>
        `;

        statsContainer.innerHTML = statsHtml;
        dashboard.style.display = 'block';

        // Show alert if there are critical certificates
        if (stats.expired > 0 || stats.critical > 0) {
            const urgentCount = stats.expired + stats.critical;
            this.showAlert(
                `⚠️ ${urgentCount} certificate${urgentCount > 1 ? 's' : ''} require${urgentCount === 1 ? 's' : ''} immediate attention!`,
                'danger'
            );
        } else if (stats.urgent > 0) {
            this.showAlert(
                `📋 ${stats.urgent} certificate${stats.urgent > 1 ? 's' : ''} should be renewed within 2 weeks`,
                'warning'
            );
        }
    }

    createCertificateCard(cert) {
        const row = document.createElement('div');
        row.className = 'certificate-list-item';

        const expiryStatus = this.getExpiryStatus(cert);
        const statusClass = this.getStatusClass(expiryStatus);
        const statusText = this.getStatusText(expiryStatus, cert.days_until_expiry);
        const cardClass = this.getCardClass(expiryStatus);
        const primaryDomain = cert.subject_common_name || (cert.san_domains && cert.san_domains[0]) || 'Unknown';
        const additionalDomains = cert.san_domains && cert.san_domains.length > 1 ? `+${cert.san_domains.length - 1} more` : '';

        row.innerHTML = `
            <div class="certificate-card ${cardClass}">
                <!-- Expiry Indicator -->
                <div class="expiry-indicator ${expiryStatus}"></div>
                
                <!-- Main Certificate Info -->
                <div class="certificate-main-info">
                    <div class="certificate-title">${cert.directory_name}</div>
                    <div class="certificate-domain">
                        ${primaryDomain} ${additionalDomains}
                    </div>
                </div>
                
                <!-- Status and Expiry Info -->
                <div class="certificate-status-section">
                    <div class="certificate-expiry-info">
                        <span class="status-badge ${statusClass}">${statusText}</span>
                        <small class="text-muted">
                            <i class="fas fa-calendar-alt me-1"></i>
                            ${this.formatDate(cert.not_valid_after)}
                        </small>
                    </div>
                    <div class="d-flex align-items-center gap-2 text-muted">
                        <small>
                            <i class="fas fa-key ${cert.has_private_key ? 'private-key-indicator' : 'private-key-missing'}"></i>
                            ${cert.has_private_key ? 'Key' : 'No Key'}
                        </small>
                        <small>
                            <i class="fas fa-shield-alt"></i>
                            ${cert.signature_algorithm || 'Unknown'}
                        </small>
                    </div>
                </div>
                
                <!-- F5XC Deployments -->
                <div class="certificate-deployments-section">
                    ${this.renderF5XCDeployments(cert.f5xc_deployments || [])}
                </div>
                
                <!-- Actions -->
                <div class="certificate-actions-section">
                    <button class="btn btn-outline-secondary btn-sm" onclick="certificateManager.showCertificateDetails('${cert.directory_name}')">
                        <i class="fas fa-eye"></i> Details
                    </button>
                    <button class="btn btn-info btn-sm" onclick="certificateManager.checkF5XCCertificate('${cert.directory_name}')" title="Check if exists in F5XC">
                        <i class="fas fa-search"></i> Check F5XC
                    </button>
                    <button class="btn btn-success btn-sm" onclick="certificateManager.createCertificateFromCard('${cert.directory_name}')" title="Create on F5XC">
                        <i class="fas fa-plus"></i> Create
                    </button>
                    <button class="btn btn-warning btn-sm" onclick="certificateManager.replaceCertificateFromCard('${cert.directory_name}')" title="Replace on F5XC">
                        <i class="fas fa-sync"></i> Replace
                    </button>
                    <button class="btn btn-danger btn-sm" onclick="certificateManager.deleteCertificateFromCard()" title="Delete from F5XC">
                        <i class="fas fa-trash"></i> Delete
                    </button>
                </div>
            </div>
        `;

        return row;
    }

    renderF5XCDeployments(deployments) {
        if (!deployments || deployments.length === 0) {
            return '<div class="f5xc-deployments empty">No F5XC deployments</div>';
        }

        const deploymentsHtml = deployments.map(deployment => {
            const timestamp = new Date(deployment.timestamp).toLocaleDateString('en-US', { 
                month: 'short', 
                day: 'numeric' 
            });
            const statusIcon = deployment.success ? '✅' : '❌';
            return `
                <div class="f5xc-deployment-item">
                    <div class="deployment-cert-name">
                        <span class="deployment-badge" title="Certificate: ${deployment.certificate_name}">
                            ${statusIcon} ${deployment.certificate_name}
                        </span>
                    </div>
                    <div class="deployment-namespace">
                        <span class="namespace-badge" title="Namespace: ${deployment.namespace}">
                            <i class="fas fa-folder-open"></i> ${deployment.namespace}
                        </span>
                    </div>
                    <small class="deployment-time">${deployment.operation} • ${timestamp} • ${deployment.tenant}</small>
                </div>
            `;
        }).join('');

        return `
            <div class="f5xc-deployments">
                <div class="f5xc-deployments-header">
                    <i class="fas fa-cloud text-primary"></i>
                    <span>F5XC Deployments</span>
                </div>
                ${deploymentsHtml}
            </div>
        `;
    }

    getExpiryStatus(cert) {
        const days = cert.days_until_expiry;
        
        if (days < 0) return 'expired';
        if (days <= 7) return 'critical';    // 1 week or less
        if (days <= 14) return 'urgent';     // 2 weeks or less
        if (days <= 30) return 'attention';  // 1 month or less
        return 'safe';                       // More than 1 month
    }

    getStatusClass(expiryStatus) {
        return `status-${expiryStatus}`;
    }

    getStatusText(expiryStatus, days) {
        switch (expiryStatus) {
            case 'expired':
                return `Expired (${Math.abs(days)} days ago)`;
            case 'critical':
                return `Critical (${days} days left)`;
            case 'urgent':
                return `Urgent (${days} days left)`;
            case 'attention':
                return `Renew Soon (${days} days left)`;
            case 'safe':
                return `Valid (${days} days left)`;
            default:
                return 'Unknown';
        }
    }

    getCardClass(expiryStatus) {
        return expiryStatus;
    }

    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    }

    async showCertificateDetails(directoryName) {
        try {
            const response = await fetch(`/api/certificate/${encodeURIComponent(directoryName)}`);
            const cert = await response.json();
            
            if (cert.error) {
                this.showAlert('Error loading certificate details: ' + cert.error, 'danger');
                return;
            }

            this.currentCertificate = cert;
            this.renderCertificateDetails(cert);
            
            const modal = new bootstrap.Modal(document.getElementById('certificateModal'));
            modal.show();
        } catch (error) {
            console.error('Error loading certificate details:', error);
            this.showAlert('Error loading certificate details: ' + error.message, 'danger');
        }
    }

    renderCertificateDetails(cert) {
        const detailsContainer = document.getElementById('certificate-details');
        
        const domainsList = cert.san_domains && cert.san_domains.length > 0 
            ? `<ul class="domain-list">${cert.san_domains.map(domain => `<li>${domain}</li>`).join('')}</ul>`
            : '<span class="text-muted">No SAN domains</span>';

        detailsContainer.innerHTML = `
            <table class="table certificate-details-table">
                <tbody>
                    <tr>
                        <th>Directory Name</th>
                        <td><code>${cert.directory_name}</code></td>
                    </tr>
                    <tr>
                        <th>Common Name</th>
                        <td>${cert.subject_common_name || '<span class="text-muted">Not specified</span>'}</td>
                    </tr>
                    <tr>
                        <th>Subject Alternative Names</th>
                        <td>${domainsList}</td>
                    </tr>
                    <tr>
                        <th>Issuer</th>
                        <td><small>${cert.issuer}</small></td>
                    </tr>
                    <tr>
                        <th>Serial Number</th>
                        <td><code>${cert.serial_number}</code></td>
                    </tr>
                    <tr>
                        <th>Valid From</th>
                        <td>${this.formatDate(cert.not_valid_before)}</td>
                    </tr>
                    <tr>
                        <th>Valid Until</th>
                        <td>${this.formatDate(cert.not_valid_after)}</td>
                    </tr>
                    <tr>
                        <th>Days Until Expiry</th>
                        <td>
                            <span class="badge ${this.getStatusClass(cert)}">${cert.days_until_expiry} days</span>
                        </td>
                    </tr>
                    <tr>
                        <th>Signature Algorithm</th>
                        <td>${cert.signature_algorithm}</td>
                    </tr>
                    <tr>
                        <th>Certificate Version</th>
                        <td>${cert.version}</td>
                    </tr>
                    <tr>
                        <th>Private Key</th>
                        <td>
                            <span class="badge ${cert.has_private_key ? 'bg-success' : 'bg-danger'}">
                                <i class="fas fa-key"></i>
                                ${cert.has_private_key ? 'Available' : 'Missing'}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <th>F5XC Deployments</th>
                        <td>
                            ${this.renderF5XCDeploymentsTable(cert)}
                        </td>
                    </tr>
                    <tr>
                        <th>Certificate Files</th>
                        <td>
                            <small class="text-muted">
                                <div><strong>Fullchain:</strong> ${cert.fullchain_path}</div>
                                <div><strong>Private Key:</strong> ${cert.privkey_path || 'Not found'}</div>
                            </small>
                        </td>
                    </tr>
                </tbody>
            </table>
        `;
    }

    renderF5XCDeploymentsTable(cert) {
        const deployments = cert.f5xc_deployments || [];
        
        if (deployments.length === 0) {
            return '<span class="text-muted">No F5XC deployments found</span>';
        }

        const deploymentsHtml = deployments.map(deployment => {
            const timestamp = new Date(deployment.timestamp).toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
            const statusIcon = deployment.success ? '✅' : '❌';
            
            return `
                <div class="deployment-detail-item mb-2">
                    <div class="d-flex align-items-center gap-2 mb-1">
                        <span class="badge bg-primary">
                            <i class="fas fa-cloud me-1"></i>${deployment.tenant}
                        </span>
                        <span class="badge bg-info">
                            <i class="fas fa-folder-open me-1"></i>${deployment.namespace}
                        </span>
                        <span class="badge ${deployment.success ? 'bg-success' : 'bg-danger'}">
                            ${statusIcon} ${deployment.operation}
                        </span>
                    </div>
                    <div class="text-muted small">
                        <strong>Certificate:</strong> ${deployment.certificate_name}<br>
                        <strong>Deployed:</strong> ${timestamp}
                    </div>
                </div>
            `;
        }).join('');

        return deploymentsHtml;
    }

    showConfirmation(title, message, confirmButtonText, onConfirm, confirmButtonClass = 'btn-primary') {
        document.getElementById('confirm-title').textContent = title;
        document.getElementById('confirm-message').innerHTML = message;
        
        const confirmButton = document.getElementById('confirm-action');
        confirmButton.textContent = confirmButtonText;
        confirmButton.className = `btn ${confirmButtonClass}`;
        
        confirmButton.onclick = () => {
            const modal = bootstrap.Modal.getInstance(document.getElementById('confirmModal'));
            modal.hide();
            onConfirm();
        };

        const modal = new bootstrap.Modal(document.getElementById('confirmModal'));
        modal.show();
    }

    // F5XC name validation function
    validateF5XCName(name) {
        // DNS1035 Label: Name should be less than 64 characters with a pattern of [a-z]([-a-z0-9]*[a-z0-9])?
        if (!name || name.length === 0) {
            return { valid: false, error: 'Name is required' };
        }
        
        if (name.length >= 64) {
            return { valid: false, error: 'Name must be less than 64 characters' };
        }
        
        // Check DNS1035 pattern: [a-z]([-a-z0-9]*[a-z0-9])?
        const dns1035Pattern = /^[a-z]([-a-z0-9]*[a-z0-9])?$/;
        if (!dns1035Pattern.test(name)) {
            return { 
                valid: false, 
                error: 'Name must start with a lowercase letter and contain only lowercase letters, numbers, and hyphens. Cannot end with a hyphen.' 
            };
        }
        
        return { valid: true };
    }

    // Show certificate action dialog with namespace selection and name validation
    showCertificateActionDialog(action, directoryName = null) {
        const actionTitle = action.charAt(0).toUpperCase() + action.slice(1);
        const modalId = 'certificateActionModal';
        
        // Create modal if it doesn't exist
        if (!document.getElementById(modalId)) {
            this.createCertificateActionModal();
        }
        
        // Populate modal content
        document.getElementById('action-modal-title').textContent = `${actionTitle} Certificate`;
        document.getElementById('action-type').value = action;
        document.getElementById('directory-name').value = directoryName || '';
        
        // Set default values - convert dots to hyphens for F5XC compliance
        const defaultName = directoryName ? directoryName.replace(/\./g, '-') : '';
        document.getElementById('f5xc-name').value = defaultName;
        document.getElementById('f5xc-namespace').value = this.getCurrentSettings().namespace || 'shared';
        
        // Clear validation
        this.clearValidation();
        
        // Show modal
        const modal = new bootstrap.Modal(document.getElementById(modalId));
        modal.show();
    }

    createCertificateActionModal() {
        const modalHtml = `
        <div class="modal fade" id="certificateActionModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="action-modal-title">Certificate Action</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <form id="certificate-action-form">
                            <input type="hidden" id="action-type" value="">
                            <input type="hidden" id="directory-name" value="">
                            
                            <div class="mb-3">
                                <label for="f5xc-name" class="form-label">F5XC Certificate Name</label>
                                <input type="text" class="form-control" id="f5xc-name" placeholder="my-certificate">
                                <div class="invalid-feedback" id="name-feedback"></div>
                                <div class="form-text">
                                    Name must be less than 64 characters, start with lowercase letter, and contain only lowercase letters, numbers, and hyphens.
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="f5xc-namespace" class="form-label">F5XC Namespace</label>
                                <input type="text" class="form-control" id="f5xc-namespace" placeholder="shared">
                                <div class="form-text">Target namespace for this certificate</div>
                            </div>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" id="execute-action-btn" onclick="executeCertificateAction()">Execute</button>
                    </div>
                </div>
            </div>
        </div>`;
        
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        
        // Add real-time validation
        document.getElementById('f5xc-name').addEventListener('input', () => {
            this.validateNameInput();
        });
    }

    validateNameInput() {
        const nameInput = document.getElementById('f5xc-name');
        const feedback = document.getElementById('name-feedback');
        const executeBtn = document.getElementById('execute-action-btn');
        
        const validation = this.validateF5XCName(nameInput.value);
        
        if (validation.valid) {
            nameInput.classList.remove('is-invalid');
            nameInput.classList.add('is-valid');
            feedback.textContent = '';
            executeBtn.disabled = false;
        } else {
            nameInput.classList.remove('is-valid');
            nameInput.classList.add('is-invalid');
            feedback.textContent = validation.error;
            executeBtn.disabled = true;
        }
    }

    clearValidation() {
        const nameInput = document.getElementById('f5xc-name');
        const feedback = document.getElementById('name-feedback');
        const executeBtn = document.getElementById('execute-action-btn');
        
        nameInput.classList.remove('is-valid', 'is-invalid');
        feedback.textContent = '';
        executeBtn.disabled = false;
        
        // Validate initial value
        setTimeout(() => this.validateNameInput(), 100);
    }

    // Updated methods for actions from certificate cards
    async createCertificateFromCard(directoryName) {
        this.showCertificateActionDialog('create', directoryName);
    }

    async replaceCertificateFromCard(directoryName) {
        this.showCertificateActionDialog('replace', directoryName);
    }

    async deleteCertificateFromCard() {
        this.showCertificateActionDialog('delete');
    }

    async checkF5XCCertificate(directoryName) {
        // Show namespace selection modal
        this.showCheckF5XCModal(directoryName);
    }

    // Legacy methods for modal actions (kept for compatibility)
    async createCertificate() {
        if (!this.currentCertificate) return;
        await this.createCertificateFromCard(this.currentCertificate.directory_name);
    }

    async replaceCertificate() {
        if (!this.currentCertificate) return;
        await this.replaceCertificateFromCard(this.currentCertificate.directory_name);
    }

    async deleteCertificate() {
        await this.deleteCertificateFromCard();
    }

    // Execute certificate action from the new modal
    async executeCertificateAction() {
        const action = document.getElementById('action-type').value;
        const certificateName = document.getElementById('f5xc-name').value;
        const namespace = document.getElementById('f5xc-namespace').value;
        const directoryName = document.getElementById('directory-name').value;
        
        // Validate inputs
        const nameValidation = this.validateF5XCName(certificateName);
        if (!nameValidation.valid) {
            this.showAlert('Please fix the certificate name: ' + nameValidation.error, 'warning');
            return;
        }
        
        if (!namespace.trim()) {
            this.showAlert('Please specify a namespace', 'warning');
            return;
        }
        
        // Hide the action modal
        const modal = bootstrap.Modal.getInstance(document.getElementById('certificateActionModal'));
        modal.hide();
        
        // Execute the action
        await this.executeF5XCActionFromCard(action, certificateName, directoryName, namespace);
    }

    async executeF5XCActionFromCard(action, certificateName, directoryName, customNamespace = null) {
        try {
            this.showAlert(`${action.charAt(0).toUpperCase() + action.slice(1)}ing certificate "${certificateName}"...`, 'info');

            // Get current settings from localStorage or use stored settings
            const currentSettings = this.getCurrentSettings();
            
            // Check if we have a password, if not, prompt for it
            if (!currentSettings.client_cert_password) {
                const password = prompt('Please enter the P12 certificate password:');
                if (!password) {
                    this.showAlert('Operation cancelled - password required', 'warning');
                    return;
                }
                currentSettings.client_cert_password = password;
                // Store temporarily for this session
                sessionStorage.setItem('f5xc-temp-password', password);
            }
            
            // Override namespace if provided
            if (customNamespace) {
                currentSettings.namespace = customNamespace;
            }

            let url, method, body;
            
            switch (action) {
                case 'create':
                    url = '/api/f5xc/create';
                    method = 'POST';
                    body = {
                        certificate_name: certificateName,
                        directory_name: directoryName,
                        settings: currentSettings
                    };
                    break;
                case 'replace':
                    url = '/api/f5xc/replace';
                    method = 'PUT';
                    body = {
                        certificate_name: certificateName,
                        directory_name: directoryName,
                        settings: currentSettings
                    };
                    break;
                case 'delete':
                    url = '/api/f5xc/delete';
                    method = 'DELETE';
                    body = {
                        certificate_name: certificateName,
                        settings: currentSettings
                    };
                    break;
                default:
                    throw new Error('Invalid action');
            }

            const response = await fetch(url, {
                method: method,
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(body)
            });

            const result = await response.json();

            if (response.ok) {
                this.showAlert(`✅ ${result.message}`, 'success');
                // Refresh tracking data and certificates after successful operation
                await this.loadTrackingData();
                await this.loadCertificates();
            } else {
                this.showAlert(`❌ Error: ${result.error}`, 'danger');
            }

        } catch (error) {
            console.error('Error executing F5XC action:', error);
            this.showAlert(`❌ Error executing action: ${error.message}`, 'danger');
        }
    }

    getCurrentSettings() {
        // Get settings from localStorage (for runtime overrides) or fallback to server settings
        const storedSettings = localStorage.getItem('f5xc-settings');
        let settings;
        
        if (storedSettings) {
            settings = JSON.parse(storedSettings);
        } else {
            // Return server settings if no localStorage settings
            settings = {
                tenant_name: this.settings?.tenant_name || '',
                namespace: this.settings?.namespace || '',
                client_cert_path: this.settings?.client_cert_path || ''
            };
        }
        
        // For F5XC operations, we need the password but don't store it in localStorage
        // Try to get it from the settings modal field, or use stored session password
        const passwordField = document.getElementById('p12-password');
        if (passwordField && passwordField.value) {
            settings.client_cert_password = passwordField.value;
            // Store temporarily in session for current operations
            sessionStorage.setItem('f5xc-temp-password', passwordField.value);
        } else {
            // Fallback to session storage if modal isn't open
            const sessionPassword = sessionStorage.getItem('f5xc-temp-password');
            if (sessionPassword) {
                settings.client_cert_password = sessionPassword;
            } else {
                // Last resort: prompt user for password
                settings.client_cert_password = '';
            }
        }
        
        return settings;
    }

    showSettings() {
        // Populate the settings form with current values
        this.populateSettingsForm();
        
        const modal = new bootstrap.Modal(document.getElementById('settingsModal'));
        modal.show();
    }

    populateSettingsForm() {
        const currentSettings = this.getCurrentSettings();
        
        document.getElementById('tenant-name').value = currentSettings.tenant_name || '';
        document.getElementById('namespace').value = currentSettings.namespace || '';
        document.getElementById('p12-path').value = currentSettings.client_cert_path || '';
        
        // Check if we have a session password and indicate it to the user
        const sessionPassword = sessionStorage.getItem('f5xc-temp-password');
        const passwordField = document.getElementById('p12-password');
        
        if (sessionPassword) {
            passwordField.value = sessionPassword;
            passwordField.placeholder = 'Password loaded from current session';
        } else {
            passwordField.value = '';
            passwordField.placeholder = 'Certificate password';
        }
    }

    async saveSettings() {
        const settings = {
            tenant_name: document.getElementById('tenant-name').value.trim(),
            namespace: document.getElementById('namespace').value.trim(),
            client_cert_path: document.getElementById('p12-path').value.trim(),
            client_cert_password: document.getElementById('p12-password').value
        };

        // Validate required fields
        if (!settings.tenant_name || !settings.namespace || !settings.client_cert_path) {
            this.showAlert('Please fill in all required fields (Tenant Name, Namespace, P12 Path)', 'warning');
            return;
        }

        try {
            const response = await fetch('/api/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(settings)
            });

            const result = await response.json();

            if (response.ok) {
                // Store settings in localStorage for immediate use (without password)
                const settingsForStorage = { ...settings };
                delete settingsForStorage.client_cert_password; // Don't store password in localStorage
                localStorage.setItem('f5xc-settings', JSON.stringify(settingsForStorage));
                
                // Store password temporarily in session for current operations
                if (settings.client_cert_password) {
                    sessionStorage.setItem('f5xc-temp-password', settings.client_cert_password);
                }
                
                this.showAlert('Settings saved successfully!', 'success');
                
                // Refresh settings
                await this.loadSettings();
                
                // Hide modal
                const modal = bootstrap.Modal.getInstance(document.getElementById('settingsModal'));
                modal.hide();
            } else {
                this.showAlert('Error: ' + result.error, 'danger');
            }
        } catch (error) {
            console.error('Error saving settings:', error);
            this.showAlert('Error saving settings: ' + error.message, 'danger');
        }
    }

    async testConnection() {
        const settings = {
            tenant_name: document.getElementById('tenant-name').value.trim(),
            namespace: document.getElementById('namespace').value.trim(),
            client_cert_path: document.getElementById('p12-path').value.trim(),
            client_cert_password: document.getElementById('p12-password').value
        };

        // Validate required fields
        if (!settings.tenant_name || !settings.namespace || !settings.client_cert_path) {
            this.showAlert('Please fill in all required fields before testing connection', 'warning');
            return;
        }

        const testButton = document.querySelector('button[onclick="testConnection()"]');
        const originalText = testButton.innerHTML;
        
        try {
            testButton.innerHTML = '<span class="loading-spinner"></span> Testing...';
            testButton.disabled = true;

            const response = await fetch('/api/settings/test', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(settings)
            });

            const result = await response.json();

            if (result.success) {
                this.showAlert(result.message, 'success');
            } else {
                this.showAlert(result.message, 'danger');
            }
        } catch (error) {
            console.error('Error testing connection:', error);
            this.showAlert('Error testing connection: ' + error.message, 'danger');
        } finally {
            testButton.innerHTML = originalText;
            testButton.disabled = false;
        }
    }

    togglePasswordVisibility() {
        const passwordField = document.getElementById('p12-password');
        const toggleIcon = document.getElementById('password-toggle-icon');
        
        if (passwordField.type === 'password') {
            passwordField.type = 'text';
            toggleIcon.className = 'fas fa-eye-slash';
        } else {
            passwordField.type = 'password';
            toggleIcon.className = 'fas fa-eye';
        }
    }

    browseP12File() {
        // Create a file input element
        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.accept = '.p12,.pfx';
        fileInput.style.display = 'none';
        
        fileInput.onchange = (event) => {
            const file = event.target.files[0];
            if (file) {
                // For security reasons, we can only get the file name in the browser
                // The user will need to provide the full path manually
                document.getElementById('p12-path').value = file.name;
                this.showAlert('File selected: ' + file.name + '. Please enter the full file path manually.', 'info');
            }
        };
        
        document.body.appendChild(fileInput);
        fileInput.click();
        document.body.removeChild(fileInput);
    }

    clearSessionPassword() {
        sessionStorage.removeItem('f5xc-temp-password');
        const passwordField = document.getElementById('p12-password');
        passwordField.value = '';
        passwordField.placeholder = 'Certificate password';
        this.showAlert('Cached password cleared', 'info');
    }

    async clearTrackingData() {
        if (!confirm('Are you sure you want to clear all F5XC deployment tracking data? This cannot be undone.')) {
            return;
        }

        try {
            const response = await fetch('/api/tracking/clear', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            const result = await response.json();

            if (response.ok) {
                this.showAlert('Tracking data cleared successfully', 'success');
                // Refresh data
                await this.loadTrackingData();
                await this.loadCertificates();
            } else {
                this.showAlert('Error: ' + result.error, 'danger');
            }
        } catch (error) {
            console.error('Error clearing tracking data:', error);
            this.showAlert('Error clearing tracking data: ' + error.message, 'danger');
        }
    }

    async executeF5XCAction(action, certificateName) {
        // Legacy method for modal actions
        await this.executeF5XCActionFromCard(action, certificateName, this.currentCertificate?.directory_name);
        
        // Hide the certificate modal
        const modal = bootstrap.Modal.getInstance(document.getElementById('certificateModal'));
        if (modal) modal.hide();
    }

    showAlert(message, type = 'info') {
        const alertContainer = document.getElementById('alert-container');
        const alertId = 'alert-' + Date.now();
        
        const alert = document.createElement('div');
        alert.id = alertId;
        alert.className = `alert alert-${type} alert-dismissible fade show`;
        alert.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        alertContainer.appendChild(alert);
        
        // Auto-dismiss after 10 seconds
        setTimeout(() => {
            const alertElement = document.getElementById(alertId);
            if (alertElement) {
                const bsAlert = new bootstrap.Alert(alertElement);
                bsAlert.close();
            }
        }, 10000);
    }

    showLoading() {
        document.getElementById('loading').style.display = 'block';
        document.getElementById('certificates-container').style.display = 'none';
        document.getElementById('empty-state').style.display = 'none';
    }

    hideLoading() {
        document.getElementById('loading').style.display = 'none';
    }
}

// Global functions for onclick handlers
function refreshCertificates() {
    certificateManager.loadCertificates();
}

function createCertificate() {
    certificateManager.createCertificate();
}

function replaceCertificate() {
    certificateManager.replaceCertificate();
}

function deleteCertificate() {
    certificateManager.deleteCertificate();
}

function showSettings() {
    certificateManager.showSettings();
}

function saveSettings() {
    certificateManager.saveSettings();
}

function testConnection() {
    certificateManager.testConnection();
}

function togglePasswordVisibility() {
    certificateManager.togglePasswordVisibility();
}

function browseP12File() {
    certificateManager.browseP12File();
}

function executeCertificateAction() {
    certificateManager.executeCertificateAction();
}

function clearSessionPassword() {
    certificateManager.clearSessionPassword();
}

function clearTrackingData() {
    certificateManager.clearTrackingData();
}

function clearFilter() {
    certificateManager.clearFilter();
}

// Initialize the application
const certificateManager = new CertificateManager();