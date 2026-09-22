'use strict';

const $ = (id) => document.getElementById(id);
let token = localStorage.getItem('securelife_token') || '';
let currentUser = null;
let policies = [];
let claims = [];
let payments = [];

const moneyFmt = new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 2 });
const dateFmt = (v) => v ? new Date(v).toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' }) : '—';
const esc = (v) => String(v ?? '').replace(/[&<>'"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const badgeClass = (s) => String(s || '').toLowerCase().replaceAll(' ', '-');

function showToast(message) {
  const el = $('toast');
  el.textContent = message;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 3200);
}
function setMessage(id, message, success=false) {
  const el = $(id);
  if (!el) return;
  el.textContent = message || '';
  el.classList.toggle('success', !!success);
}
async function api(url, options={}) {
  const headers = { ...(options.headers || {}) };
  if (options.body && !(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(url, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && token) logout(false);
    throw new Error(data.error || 'Request failed.');
  }
  return data;
}
function hideViews() {
  ['publicView','authView','userView','adminView'].forEach(id => $(id).classList.add('hidden'));
}
function showPublic() {
  hideViews();
  $('publicView').classList.remove('hidden');
  $('portalBtn').classList.remove('hidden');
  $('logoutBtn').classList.add('hidden');
}
function showAuth() {
  hideViews();
  $('authView').classList.remove('hidden');
  $('portalBtn').classList.add('hidden');
  $('logoutBtn').classList.toggle('hidden', !token);
}
function logout(toPublic=true) {
  token='';
  currentUser=null;
  localStorage.removeItem('securelife_token');
  if (toPublic) showPublic();
}
function stat(label, value) {
  return `<div class="stat"><strong>${esc(value)}</strong><span>${esc(label)}</span></div>`;
}
function listEmpty(text) {
  return `<div class="empty">${esc(text)}</div>`;
}

async function boot() {
  bindEvents();
  if (!token) return showPublic();
  try {
    currentUser = await api('/api/me');
    await openPortal();
  } catch {
    logout();
  }
}
async function openPortal() {
  if (!token) return showAuth();
  if (!currentUser) currentUser = await api('/api/me');
  hideViews();
  $('logoutBtn').classList.remove('hidden');
  $('portalBtn').classList.add('hidden');
  if (currentUser.role === 'ADMIN') {
    $('adminView').classList.remove('hidden');
    $('adminEmail').textContent = currentUser.email;
    await loadAdmin();
  } else {
    $('userView').classList.remove('hidden');
    $('userGreeting').textContent = `Hi, ${currentUser.name}`;
    $('userEmail').textContent = currentUser.email;
    await loadUserData();
  }
}

async function loadUserData() {
  [policies, claims, payments] = await Promise.all([
    api('/api/policies'),
    api('/api/claims'),
    api('/api/payments')
  ]);
  renderUser();
}
function renderUser() {
  const active = policies.filter(p=>p.status==='Active').length;
  const pending = policies.filter(p=>p.status==='Pending').length;
  const openClaims = claims.filter(c=>['Submitted','Under Review'].includes(c.status)).length;
  $('userStats').innerHTML =
    stat('Active policies', active) +
    stat('Pending applications', pending) +
    stat('Open claims', openClaims) +
    stat('Payment records', payments.length);

  const activity = [
    ...policies.map(x=>({date:x.created_at,text:`Policy application: ${x.policy_type} · ${x.status}`})),
    ...claims.map(x=>({date:x.created_at,text:`Claim #${x.id} · ${x.status}`})),
    ...payments.map(x=>({date:x.created_at,text:`Payment ${x.reference} · ${x.status}`}))
  ].sort((a,b)=>new Date(b.date)-new Date(a.date)).slice(0,6);

  $('recentActivity').innerHTML = activity.length
    ? activity.map(a=>`<div class="list-item"><strong>${esc(a.text)}</strong><div class="meta">${dateFmt(a.date)}</div></div>`).join('')
    : listEmpty('No activity yet.');

  $('policyList').innerHTML = policies.length
    ? policies.map(p=>`<article class="list-item"><h4>${esc(p.policy_type)} · ${esc(p.plan)}</h4><div class="meta"><span>${p.policy_number?esc(p.policy_number):'Application #'+p.id}</span><span>Coverage ${moneyFmt.format(p.coverage)}</span><span>Premium ${p.premium?moneyFmt.format(p.premium):'Awaiting review'}</span><span>Renewal ${dateFmt(p.renewal_date)}</span><span class="badge ${badgeClass(p.status)}">${esc(p.status)}</span></div></article>`).join('')
    : listEmpty('No policy applications yet.');

  $('claimList').innerHTML = claims.length
    ? claims.map(c=>`<article class="list-item"><h4>Claim #${c.id} · ${esc(c.policy_type)}</h4><p>${esc(c.description)}</p><div class="meta"><span>${moneyFmt.format(c.amount)}</span><span>${dateFmt(c.created_at)}</span><span class="badge ${badgeClass(c.status)}">${esc(c.status)}</span></div></article>`).join('')
    : listEmpty('No claims submitted.');

  $('paymentList').innerHTML = payments.length
    ? payments.map(p=>`<article class="list-item"><h4>${esc(p.reference)}</h4><div class="meta"><span>${esc(p.policy_type)}</span><span>${moneyFmt.format(p.amount)}</span><span>${dateFmt(p.created_at)}</span><span class="badge ${badgeClass(p.status)}">${esc(p.status)}</span></div></article>`).join('')
    : listEmpty('No payment records.');

  const activePolicies = policies.filter(p=>p.status==='Active');
  const opts = activePolicies.length
    ? activePolicies.map(p=>`<option value="${p.id}">${esc(p.policy_number||'#'+p.id)} · ${esc(p.policy_type)}</option>`).join('')
    : '<option value="">No active policy available</option>';
  $('claimPolicy').innerHTML = opts;
  $('paymentPolicy').innerHTML = opts;
}

async function loadAdmin() {
  const [stats, users, aps, acs, apy, contacts] = await Promise.all([
    api('/api/admin/stats'),
    api('/api/admin/users'),
    api('/api/admin/policies'),
    api('/api/admin/claims'),
    api('/api/admin/payments'),
    api('/api/admin/contacts')
  ]);

  $('adminStats').innerHTML =
    stat('Customers',stats.users)+
    stat('Policies',stats.policies)+
    stat('Pending policies',stats.pending_policies)+
    stat('Open claims',stats.open_claims)+
    stat('New enquiries',stats.new_contacts);

  $('adminUsersBody').innerHTML = users.map(u=>`<tr><td>${esc(u.name)}</td><td>${esc(u.email)}</td><td><span class="badge">${esc(u.role)}</span></td><td>${dateFmt(u.created_at)}</td></tr>`).join('')
    || '<tr><td colspan="4">No users.</td></tr>';

  $('adminPoliciesBody').innerHTML = aps.map(p=>`<tr><td><strong>${esc(p.user_name)}</strong><br><span class="muted">${esc(p.user_email)}</span></td><td>${esc(p.policy_type)}<br><span class="muted">${esc(p.plan)} · ${esc(p.policy_number||'Not assigned')}</span></td><td>${moneyFmt.format(p.coverage)}</td><td><input type="number" min="1" id="premium-${p.id}" value="${p.premium||''}" placeholder="Premium"></td><td><select id="pstatus-${p.id}">${['Pending','Active','Rejected','Expired','Cancelled'].map(s=>`<option ${p.status===s?'selected':''}>${s}</option>`).join('')}</select></td><td><button class="mini-btn" data-policy-save="${p.id}">Save</button></td></tr>`).join('')
    || '<tr><td colspan="6">No policies.</td></tr>';

  $('adminClaimsBody').innerHTML = acs.map(c=>`<tr><td><strong>${esc(c.user_name)}</strong><br><span class="muted">${esc(c.user_email)}</span></td><td>${esc(c.policy_number||'#'+c.policy_id)}</td><td>${moneyFmt.format(c.amount)}</td><td>${esc(c.description)}</td><td><select id="cstatus-${c.id}">${['Submitted','Under Review','Approved','Rejected','Paid'].map(s=>`<option ${c.status===s?'selected':''}>${s}</option>`).join('')}</select></td><td><button class="mini-btn" data-claim-save="${c.id}">Save</button></td></tr>`).join('')
    || '<tr><td colspan="6">No claims.</td></tr>';

  $('adminPaymentsBody').innerHTML = apy.map(p=>`<tr><td><strong>${esc(p.user_name)}</strong><br><span class="muted">${esc(p.user_email)}</span></td><td>${esc(p.policy_number||'#'+p.policy_id)}</td><td>${moneyFmt.format(p.amount)}</td><td>${esc(p.reference)}</td><td><select id="paystatus-${p.id}">${['Recorded','Verified','Rejected'].map(s=>`<option ${p.status===s?'selected':''}>${s}</option>`).join('')}</select></td><td><button class="mini-btn" data-payment-save="${p.id}">Save</button></td></tr>`).join('')
    || '<tr><td colspan="6">No payment records.</td></tr>';

  $('adminContactsBody').innerHTML = contacts.map(c=>`<tr><td><strong>${esc(c.name)}</strong><br><span class="muted">${esc(c.insurance||'General')}</span></td><td>${esc(c.email)}<br><span class="muted">${esc(c.phone||'')}</span></td><td>${esc(c.message)}</td><td><select id="contactstatus-${c.id}">${['New','Contacted','Closed'].map(s=>`<option ${c.status===s?'selected':''}>${s}</option>`).join('')}</select></td><td><button class="mini-btn" data-contact-save="${c.id}">Save</button></td></tr>`).join('')
    || '<tr><td colspan="5">No enquiries.</td></tr>';
}

function bindEvents() {
  $('menuBtn').addEventListener('click',()=> $('nav').classList.toggle('open'));
  $('portalBtn').addEventListener('click',()=> token ? openPortal() : showAuth());
  $('heroPortalBtn').addEventListener('click',()=> token ? openPortal() : showAuth());
  $('logoutBtn').addEventListener('click',()=> logout());

  document.querySelectorAll('[data-nav]').forEach(a=>a.addEventListener('click',()=>{
    showPublic();
    $('nav').classList.remove('open');
  }));

  document.querySelectorAll('.tab').forEach(btn=>btn.addEventListener('click',()=>{
    document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    $('loginPanel').classList.toggle('hidden',btn.dataset.tab!=='login');
    $('registerPanel').classList.toggle('hidden',btn.dataset.tab!=='register');
  }));

  document.querySelectorAll('[data-section]').forEach(btn=>btn.addEventListener('click',()=> switchUserPanel(btn.dataset.section)));
  document.querySelectorAll('[data-jump]').forEach(btn=>btn.addEventListener('click',()=>switchUserPanel(btn.dataset.jump)));
  document.querySelectorAll('[data-admin-section]').forEach(btn=>btn.addEventListener('click',()=>switchAdminPanel(btn.dataset.adminSection)));

  $('loginForm').addEventListener('submit', async e=>{
    e.preventDefault();
    setMessage('loginMsg','');
    try {
      const data=await api('/api/auth/login',{method:'POST',body:JSON.stringify({email:$('loginEmail').value,password:$('loginPassword').value})});
      token=data.token;
      currentUser=data.user;
      localStorage.setItem('securelife_token',token);
      $('loginForm').reset();
      await openPortal();
    } catch(err) { setMessage('loginMsg',err.message); }
  });

  $('registerForm').addEventListener('submit', async e=>{
    e.preventDefault();
    setMessage('registerMsg','');
    try {
      const data=await api('/api/auth/register',{method:'POST',body:JSON.stringify({name:$('registerName').value,email:$('registerEmail').value,password:$('registerPassword').value})});
      token=data.token;
      currentUser=data.user;
      localStorage.setItem('securelife_token',token);
      $('registerForm').reset();
      await openPortal();
    } catch(err) { setMessage('registerMsg',err.message); }
  });

  $('contactForm').addEventListener('submit', async e=>{
    e.preventDefault();
    setMessage('contactMsg','');
    try {
      const data=await api('/api/contacts',{method:'POST',body:JSON.stringify({
        name:$('contactName').value,email:$('contactEmail').value,phone:$('contactPhone').value,
        insurance:$('contactInsurance').value,message:$('contactMessage').value
      })});
      $('contactForm').reset();
      setMessage('contactMsg',data.message,true);
    } catch(err) { setMessage('contactMsg',err.message); }
  });

  $('policyForm').addEventListener('submit', async e=>{
    e.preventDefault();
    setMessage('policyMsg','');
    try {
      const data=await api('/api/policies',{method:'POST',body:JSON.stringify({
        policyType:$('policyType').value,plan:$('policyPlan').value,coverage:$('policyCoverage').value
      })});
      $('policyForm').reset();
      setMessage('policyMsg',data.message,true);
      await loadUserData();
    } catch(err) { setMessage('policyMsg',err.message); }
  });

  $('claimForm').addEventListener('submit', async e=>{
    e.preventDefault();
    setMessage('claimMsg','');
    try {
      const data=await api('/api/claims',{method:'POST',body:JSON.stringify({
        policyId:$('claimPolicy').value,amount:$('claimAmount').value,description:$('claimDescription').value
      })});
      $('claimForm').reset();
      setMessage('claimMsg',data.message,true);
      await loadUserData();
    } catch(err) { setMessage('claimMsg',err.message); }
  });

  $('paymentForm').addEventListener('submit', async e=>{
    e.preventDefault();
    setMessage('paymentMsg','');
    try {
      const data=await api('/api/payments',{method:'POST',body:JSON.stringify({
        policyId:$('paymentPolicy').value,amount:$('paymentAmount').value
      })});
      $('paymentForm').reset();
      setMessage('paymentMsg',data.message,true);
      await loadUserData();
    } catch(err) { setMessage('paymentMsg',err.message); }
  });

  $('passwordForm').addEventListener('submit', async e=>{
    e.preventDefault();
    setMessage('passwordMsg','');
    try {
      const data=await api('/api/me/password',{method:'PUT',body:JSON.stringify({
        currentPassword:$('currentPassword').value,newPassword:$('newPassword').value
      })});
      $('passwordForm').reset();
      setMessage('passwordMsg',data.message,true);
    } catch(err) { setMessage('passwordMsg',err.message); }
  });

  document.addEventListener('click', async e=>{
    const p=e.target.closest('[data-policy-save]');
    if(p){
      try {
        await api(`/api/admin/policies/${p.dataset.policySave}`,{
          method:'PATCH',
          body:JSON.stringify({
            status:$(`pstatus-${p.dataset.policySave}`).value,
            premium:$(`premium-${p.dataset.policySave}`).value
          })
        });
        showToast('Policy updated');
        await loadAdmin();
      } catch(err) { showToast(err.message); }
      return;
    }

    const c=e.target.closest('[data-claim-save]');
    if(c){
      try {
        await api(`/api/admin/claims/${c.dataset.claimSave}`,{
          method:'PATCH',
          body:JSON.stringify({status:$(`cstatus-${c.dataset.claimSave}`).value})
        });
        showToast('Claim updated');
        await loadAdmin();
      } catch(err) { showToast(err.message); }
      return;
    }

    const py=e.target.closest('[data-payment-save]');
    if(py){
      try {
        await api(`/api/admin/payments/${py.dataset.paymentSave}`,{
          method:'PATCH',
          body:JSON.stringify({status:$(`paystatus-${py.dataset.paymentSave}`).value})
        });
        showToast('Payment updated');
        await loadAdmin();
      } catch(err) { showToast(err.message); }
      return;
    }

    const ct=e.target.closest('[data-contact-save]');
    if(ct){
      try {
        await api(`/api/admin/contacts/${ct.dataset.contactSave}`,{
          method:'PATCH',
          body:JSON.stringify({status:$(`contactstatus-${ct.dataset.contactSave}`).value})
        });
        showToast('Enquiry updated');
        await loadAdmin();
      } catch(err) { showToast(err.message); }
    }
  });
}

function switchUserPanel(name){
  document.querySelectorAll('[data-section]').forEach(b=>b.classList.toggle('active',b.dataset.section===name));
  document.querySelectorAll('[data-panel]').forEach(p=>p.classList.toggle('hidden',p.dataset.panel!==name));
}
function switchAdminPanel(name){
  document.querySelectorAll('[data-admin-section]').forEach(b=>b.classList.toggle('active',b.dataset.adminSection===name));
  document.querySelectorAll('[data-admin-panel]').forEach(p=>p.classList.toggle('hidden',p.dataset.adminPanel!==name));
}

boot();
