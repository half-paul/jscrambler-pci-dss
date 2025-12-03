/**
 * Script Details Module
 * Handles viewing and editing detailed script information
 */

// Script Details Modal
async function showScriptDetails(scriptId) {
    document.getElementById('scriptDetailsModal').classList.add('active');
    document.getElementById('scriptDetailsContent').innerHTML = '<div class="loading">Loading script details...</div>';
    document.getElementById('scriptDetailsError').style.display = 'none';
    isEditMode = false;

    try {
        const data = await apiCall(`/api/admin/scripts/${scriptId}`);
        const script = data.script;
        const auditLog = data.auditLog || [];

        // Store for editing
        currentScriptDetails = { script, auditLog };

        const statusColors = {
            'approved': 'success',
            'pending_approval': 'warning',
            'rejected': 'danger',
            'flagged': 'warning'
        };

        const statusLabels = {
            'approved': 'Approved',
            'pending_approval': 'Pending Approval',
            'rejected': 'Rejected',
            'flagged': 'Flagged'
        };

        document.getElementById('scriptDetailsContent').innerHTML = `
            <div style="display: grid; gap: 30px;">
                <!-- Basic Information -->
                <div>
                    <h3 style="margin-bottom: 15px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">Basic Information</h3>
                    <div class="info-grid">
                        <div class="info-label">ID:</div>
                        <div>${script.id}</div>

                        <div class="info-label">URL:</div>
                        <div style="word-break: break-all;">${escapeHtml(script.url)}</div>

                        <div class="info-label">Type:</div>
                        <div><span class="badge">${script.script_type}</span></div>

                        <div class="info-label">Status:</div>
                        <div><span class="badge ${statusColors[script.status] || ''}">${statusLabels[script.status] || script.status}</span></div>

                        <div class="info-label">Size:</div>
                        <div>${script.size_bytes ? (script.size_bytes / 1024).toFixed(2) + ' KB' : '-'}</div>

                        <div class="info-label">First Seen:</div>
                        <div>${new Date(script.first_seen).toLocaleString()}</div>

                        <div class="info-label">Last Seen:</div>
                        <div>${new Date(script.last_seen).toLocaleString()}</div>

                        <div class="info-label">Access Count:</div>
                        <div><strong style="color: #3498db; font-size: 16px;">${script.access_count || 0}</strong> <span style="color: #7f8c8d; font-size: 12px;">(times loaded)</span></div>

                        ${script.last_accessed ? `
                        <div class="info-label">Last Accessed:</div>
                        <div>${new Date(script.last_accessed).toLocaleString()}</div>
                        ` : ''}

                        ${script.script_type === 'inline' && script.script_position !== null && script.script_position !== undefined ? `
                        <div class="info-label">Script Position:</div>
                        <div>${script.script_position} <span style="color: #7f8c8d; font-size: 12px;">(index in page)</span></div>
                        ` : ''}

                        ${script.is_variation ? `
                        <div class="info-label">Variation:</div>
                        <div>
                            <span class="badge warning">Variation #${script.variation_number}</span>
                            <span style="color: #7f8c8d; font-size: 12px;">of <a href="#" onclick="showScriptDetails(${script.parent_script_id}); return false;">Script #${script.parent_script_id}</a></span>
                        </div>
                        ` : ''}

                        ${script.parent_script_id === null && script.variation_number ? `
                        <div class="info-label">Original Script:</div>
                        <div><span class="badge success">Variation #${script.variation_number}</span> <span style="color: #7f8c8d; font-size: 12px;">(parent of variations)</span></div>
                        ` : ''}

                        <div class="info-label">Last Loaded From:</div>
                        <div style="word-break: break-all;">${escapeHtml(script.page_url)}</div>

                        <div class="info-label">Discovery Context:</div>
                        <div style="font-family: monospace; font-size: 12px; word-break: break-all;">${script.discovery_context || '-'}</div>
                    </div>
                </div>

                <!-- Hash Information -->
                <div>
                    <h3 style="margin-bottom: 15px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">Hash Information</h3>
                    <div class="info-grid">
                        <div class="info-label">Content Hash:</div>
                        <div style="font-family: monospace; font-size: 12px; word-break: break-all;">${escapeHtml(script.content_hash)}</div>
                    </div>
                </div>

                <!-- Content Preview -->
                ${script.content_preview ? `
                <div>
                    <h3 style="margin-bottom: 15px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">Content Preview</h3>
                    <pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; max-height: 200px; font-size: 12px;">${escapeHtml(script.content_preview)}</pre>
                </div>
                ` : ''}

                <!-- Approval Information -->
                ${script.status === 'approved' || script.status === 'rejected' ? `
                <div>
                    <h3 style="margin-bottom: 15px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">${script.status === 'approved' ? 'Approval' : 'Rejection'} Information</h3>
                    <div class="info-grid">
                        <div class="info-label">${script.status === 'approved' ? 'Approved By' : 'Rejected By'}:</div>
                        <div>${script.approved_by || '-'}</div>

                        <div class="info-label">${script.status === 'approved' ? 'Approved At' : 'Rejected At'}:</div>
                        <div>${script.approved_at ? new Date(script.approved_at).toLocaleString() : '-'}</div>

                        ${script.status === 'approved' ? `
                        <div class="info-label">Business Justification:</div>
                        <div>${script.business_justification || '-'}</div>

                        <div class="info-label">Script Purpose:</div>
                        <div>${script.script_purpose || '-'}</div>

                        <div class="info-label">Script Owner:</div>
                        <div>${script.script_owner || '-'}</div>

                        <div class="info-label">Risk Level:</div>
                        <div>${script.risk_level ? `<span class="badge ${script.risk_level}">${script.risk_level}</span>` : '-'}</div>
                        ` : `
                        <div class="info-label">Rejection Reason:</div>
                        <div>${script.rejection_reason || '-'}</div>
                        `}

                        <div class="info-label">Notes:</div>
                        <div>${script.approval_notes || '-'}</div>
                    </div>
                </div>
                ` : ''}

                <!-- Audit Log -->
                ${auditLog.length > 0 ? `
                <div>
                    <h3 style="margin-bottom: 15px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">Audit Log</h3>
                    <table style="width: 100%;">
                        <thead>
                            <tr>
                                <th>Action</th>
                                <th>Status Change</th>
                                <th>Performed By</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${auditLog.map(log => `
                                <tr>
                                    <td><span class="badge">${log.action}</span></td>
                                    <td>${log.previous_status || '-'} → ${log.new_status}</td>
                                    <td>${log.performed_by}</td>
                                    <td>${new Date(log.performed_at).toLocaleString()}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                ` : ''}
            </div>
        `;

        // Show edit button
        document.getElementById('editScriptBtn').style.display = 'inline-block';
        document.getElementById('saveScriptBtn').style.display = 'none';
        document.getElementById('cancelEditBtn').style.display = 'none';
        document.getElementById('closeDetailsBtn').style.display = 'inline-block';

    } catch (err) {
        document.getElementById('scriptDetailsContent').innerHTML = `
            <div class="error-message" style="display: block;">
                Failed to load script details: ${err.message}
            </div>
        `;
    }
}

function toggleEditMode() {
    isEditMode = true;
    renderEditMode();
}

function renderEditMode() {
    if (!currentScriptDetails) return;

    const script = currentScriptDetails.script;

    document.getElementById('scriptDetailsContent').innerHTML = `
        <div style="display: grid; gap: 20px;">
            <div class="form-group">
                <label for="editStatus">Status *</label>
                <select id="editStatus">
                    <option value="pending_approval" ${script.status === 'pending_approval' ? 'selected' : ''}>Pending Approval</option>
                    <option value="approved" ${script.status === 'approved' ? 'selected' : ''}>Approved</option>
                    <option value="rejected" ${script.status === 'rejected' ? 'selected' : ''}>Rejected</option>
                    <option value="flagged" ${script.status === 'flagged' ? 'selected' : ''}>Flagged</option>
                </select>
            </div>

            <div class="form-group">
                <label for="editBusinessJustification">Business Justification</label>
                <textarea id="editBusinessJustification" rows="3">${script.business_justification || ''}</textarea>
            </div>

            <div class="form-group">
                <label for="editScriptPurpose">Script Purpose</label>
                <input type="text" id="editScriptPurpose" value="${escapeHtml(script.script_purpose || '')}">
            </div>

            <div class="form-group">
                <label for="editScriptOwner">Script Owner</label>
                <input type="text" id="editScriptOwner" value="${escapeHtml(script.script_owner || '')}">
            </div>

            <div class="form-group">
                <label for="editRiskLevel">Risk Level</label>
                <select id="editRiskLevel">
                    <option value="">None</option>
                    <option value="low" ${script.risk_level === 'low' ? 'selected' : ''}>Low</option>
                    <option value="medium" ${script.risk_level === 'medium' ? 'selected' : ''}>Medium</option>
                    <option value="high" ${script.risk_level === 'high' ? 'selected' : ''}>High</option>
                    <option value="critical" ${script.risk_level === 'critical' ? 'selected' : ''}>Critical</option>
                </select>
            </div>

            <div class="form-group">
                <label for="editApprovalNotes">Notes</label>
                <textarea id="editApprovalNotes" rows="3">${script.approval_notes || ''}</textarea>
            </div>

            <div class="form-group">
                <label for="editRejectionReason">Rejection Reason (if rejected)</label>
                <textarea id="editRejectionReason" rows="2">${script.rejection_reason || ''}</textarea>
            </div>

            <div style="padding: 15px; background: #f8f9fa; border-radius: 4px;">
                <h4 style="margin: 0 0 10px 0; color: #666;">Read-Only Information</h4>
                <div class="info-grid">
                    <div class="info-label">ID:</div>
                    <div>${script.id}</div>
                    <div class="info-label">URL:</div>
                    <div style="word-break: break-all;">${escapeHtml(script.url)}</div>
                    <div class="info-label">Type:</div>
                    <div>${script.script_type}</div>
                    <div class="info-label">First Seen:</div>
                    <div>${new Date(script.first_seen).toLocaleString()}</div>
                    <div class="info-label">Last Seen:</div>
                    <div>${new Date(script.last_seen).toLocaleString()}</div>
                    <div class="info-label">Access Count:</div>
                    <div><strong style="color: #3498db;">${script.access_count || 0}</strong></div>
                    ${script.last_accessed ? `
                    <div class="info-label">Last Accessed:</div>
                    <div>${new Date(script.last_accessed).toLocaleString()}</div>
                    ` : ''}
                    ${script.script_type === 'inline' && script.script_position !== null && script.script_position !== undefined ? `
                    <div class="info-label">Script Position:</div>
                    <div>${script.script_position}</div>
                    ` : ''}
                    ${script.is_variation ? `
                    <div class="info-label">Variation:</div>
                    <div><span class="badge warning">Variation #${script.variation_number}</span> of Script #${script.parent_script_id}</div>
                    ` : ''}
                    ${script.approved_at ? `
                    <div class="info-label">Approved/Rejected At:</div>
                    <div>${new Date(script.approved_at).toLocaleString()}</div>
                    ` : ''}
                    ${script.approved_by ? `
                    <div class="info-label">Approved/Rejected By:</div>
                    <div>${script.approved_by}</div>
                    ` : ''}
                </div>
            </div>
        </div>
    `;

    // Update buttons
    document.getElementById('editScriptBtn').style.display = 'none';
    document.getElementById('saveScriptBtn').style.display = 'inline-block';
    document.getElementById('cancelEditBtn').style.display = 'inline-block';
    document.getElementById('closeDetailsBtn').style.display = 'none';
}

async function saveScriptChanges() {
    if (!currentScriptDetails) return;

    const scriptId = currentScriptDetails.script.id;
    const updateData = {
        status: document.getElementById('editStatus').value,
        businessJustification: document.getElementById('editBusinessJustification').value,
        scriptPurpose: document.getElementById('editScriptPurpose').value,
        scriptOwner: document.getElementById('editScriptOwner').value,
        riskLevel: document.getElementById('editRiskLevel').value || null,
        approvalNotes: document.getElementById('editApprovalNotes').value,
        rejectionReason: document.getElementById('editRejectionReason').value
    };

    try {
        await apiCall(`/api/admin/scripts/${scriptId}/update`, {
            method: 'PUT',
            body: JSON.stringify(updateData)
        });

        document.getElementById('scriptDetailsError').style.display = 'none';

        // Reload script details
        await showScriptDetails(scriptId);

        // Refresh the inventory table
        fetchInventory();

    } catch (err) {
        document.getElementById('scriptDetailsError').textContent = 'Failed to save changes: ' + err.message;
        document.getElementById('scriptDetailsError').style.display = 'block';
    }
}

function cancelEdit() {
    if (!currentScriptDetails) return;

    // Redisplay in view mode
    showScriptDetails(currentScriptDetails.script.id);
}

function closeScriptDetailsModal() {
    document.getElementById('scriptDetailsModal').classList.remove('active');
    isEditMode = false;
    currentScriptDetails = null;
}

