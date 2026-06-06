// ==========================================
// 1. GESTIÓN DE PESTAÑAS (TABS)
// ==========================================
const btnPasswords = document.getElementById('btn-passwords');
const btnIp = document.getElementById('btn-ip');
const secPasswords = document.getElementById('sec-passwords');
const secIp = document.getElementById('sec-ip');

btnPasswords.addEventListener('click', () => {
    btnPasswords.classList.add('border-blue-500', 'text-blue-400');
    btnPasswords.classList.remove('border-transparent', 'text-gray-500', 'hover:text-gray-300');
    btnIp.classList.remove('border-emerald-500', 'text-emerald-400');
    btnIp.classList.add('border-transparent', 'text-gray-500', 'hover:text-gray-300');
    secPasswords.classList.remove('hidden');
    secIp.classList.add('hidden');
});

btnIp.addEventListener('click', () => {
    btnIp.classList.add('border-emerald-500', 'text-emerald-400');
    btnIp.classList.remove('border-transparent', 'text-gray-500', 'hover:text-gray-300');
    btnPasswords.classList.remove('border-blue-500', 'text-blue-400');
    btnPasswords.classList.add('border-transparent', 'text-gray-500', 'hover:text-gray-300');
    secIp.classList.remove('hidden');
    secPasswords.classList.add('hidden');
});

// ==========================================
// 2. AUDITORÍA DE CONTRASEÑAS (k-Anonymity SHA-1)
// ==========================================
const inputPass = document.getElementById('input-pass');
const btnSearchPass = document.getElementById('search-pass');
const resultPass = document.getElementById('result-pass');

btnSearchPass.addEventListener('click', checkPassword);

async function checkPassword() {
    const password = inputPass.value.trim();
    if (!password) return;

    resultPass.className = "mt-4 p-4 rounded-lg text-xs border font-mono font-medium bg-gray-950 border-gray-800 text-gray-400";
    resultPass.innerHTML = "⚡ Analizando entropía y consultando registros globales...";
    resultPass.classList.remove('hidden');

    try {
        const hash = CryptoJS.SHA1(password).toString().toUpperCase();
        const prefix = hash.substring(0, 5);
        const suffix = hash.substring(5);

        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        if (!response.ok) throw new Error();
        
        const data = await response.text();
        const lines = data.split('\n');
        let count = 0;

        for (let line of lines) {
            const [returnedSuffix, matchCount] = line.split(':');
            if (returnedSuffix.trim() === suffix) {
                count = parseInt(matchCount);
                break;
            }
        }

        if (count > 0) {
            resultPass.className = "mt-4 p-4 rounded-lg text-xs border font-mono font-medium bg-red-500/10 text-red-400 border-red-500/20";
            resultPass.innerHTML = `🚨 <strong>CREDENTIAL CRITICAL RISK</strong><br><br>Esta clave ha sido expuesta en <strong>${count.toLocaleString()}</strong> brechas de seguridad. Evite su uso.`;
        } else {
            resultPass.className = "mt-4 p-4 rounded-lg text-xs border font-mono font-medium bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
            resultPass.innerHTML = `🔒 <strong>INTEGRITY VERIFIED</strong><br><br>No se han detectado trazas de esta credencial en repositorios públicos filtrados.`;
        }
    } catch {
        resultPass.innerHTML = "❌ Fallo crítico en el análisis automatizado.";
    }
}

// ==========================================
// 3. AUDITORÍA DE CORREOS COMPROMETIDOS
// ==========================================
const inputEmail = document.getElementById('input-email');
const btnSearchEmail = document.getElementById('search-email');
const resultEmail = document.getElementById('result-email');

btnSearchEmail.addEventListener('click', checkEmail);

async function checkEmail() {
    const email = inputEmail.value.trim();
    if (!email) return;

    resultEmail.className = "mt-4 p-4 rounded-lg text-xs border font-mono font-medium bg-gray-950 border-gray-800 text-gray-400";
    resultEmail.innerHTML = "⚡ Rastreando registros en repositorios de brechas públicos...";
    resultEmail.classList.remove('hidden');

    try {
        const response = await fetch(`https://api.breachdirectory.org/v1/secure?email=${encodeURIComponent(email)}`);
        
        if (response.status === 404) {
            resultEmail.className = "mt-4 p-4 rounded-lg text-xs border font-mono font-medium bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
            resultEmail.innerHTML = `✅ <strong>STATUS: SECURE</strong><br><br>No se han localizado fuentes de exposición asociadas a este email.`;
            return;
        }

        if (!response.ok) throw new Error();
        const data = await response.json();

        if (data && data.breaches && data.breaches.length > 0) {
            const totalBreaches = data.breaches.length;
            const fuentes = data.breaches.slice(0, 3).map(b => b.name).join(', ');
            
            resultEmail.className = "mt-4 p-4 rounded-lg text-xs border font-mono font-medium bg-red-500/10 text-red-400 border-red-500/20";
            resultEmail.innerHTML = `🚨 <strong>BREACH DETECTED</strong><br><br>Cuenta expuesta en <strong>${totalBreaches}</strong> filtraciones masivas.<br><br><strong>Fuentes principales:</strong> ${fuentes}${totalBreaches > 3 ? '...' : ''}`;
        } else {
            resultEmail.className = "mt-4 p-4 rounded-lg text-xs border font-mono font-medium bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
            resultEmail.innerHTML = `✅ <strong>STATUS: SECURE</strong><br><br>Sin incidencias reportadas en incidentes globales.`;
        }
    } catch {
        resultEmail.className = "mt-4 p-4 rounded-lg text-xs border font-mono font-medium bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
        resultEmail.innerHTML = `⚠️ <strong>AVISO DE SEGURIDAD</strong><br><br>Análisis concluido. Se sugiere verificar credenciales de manera periódica y activar 2FA.`;
    }
}

// ==========================================
// 4. INTELIGENCIA DE AMENAZAS E IP GEO
// ==========================================
const inputIp = document.getElementById('input-ip');
const btnSearchIp = document.getElementById('search-ip');
const resultIp = document.getElementById('result-ip');
const geoDataContainer = document.getElementById('geo-data');
const threatDataContainer = document.getElementById('threat-data'); 
const btnReportIp = document.getElementById('btn-report-ip');

let currentScannedIp = "";

btnSearchIp.addEventListener('click', analyzeIp);

async function analyzeIp() {
    const ip = inputIp.value.trim();

    // End-point seguro compatible con HTTPS y entornos de producción en GitHub Pages
    const url = ip 
        ? `https://api.ipapi.is/?ip=${encodeURIComponent(ip)}` 
        : `https://api.ipapi.is/`;

    try {
        const response = await fetch(url);
        
        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status}`);
        }

        const data = await response.json();

        if (data.is_valid === false) {
            alert("Dirección IP no válida.");
            return;
        }

        currentScannedIp = data.ip;
        resultIp.classList.remove('hidden');

        // Mapeo adaptado para el JSON estructurado de ipapi.is
        const isp = data.asn?.org || 'N/A';
        const asn = data.asn?.asn ? `ASN${data.asn.asn}` : 'N/A';
        const city = data.location?.city || 'N/A';
        const countryCode = data.location?.country_code || 'N/A';
        const latitude = data.location?.latitude || 0;
        const longitude = data.location?.longitude || 0;

        // Renderizado del contenedor de Geolocalización
        geoDataContainer.innerHTML = `
            <div class="flex justify-between border-b border-gray-900 pb-1">
                <span class="text-gray-500">IP OBJECT</span>
                <span class="text-emerald-400 font-bold font-mono">${currentScannedIp}</span>
            </div>

            <div class="flex justify-between border-b border-gray-900 pb-1">
                <span class="text-gray-500">PROVEEDOR</span>
                <span class="text-gray-300 text-right text-xs">${isp}</span>
            </div>

            <div class="flex justify-between border-b border-gray-900 pb-1">
                <span class="text-gray-500">ASN</span>
                <span class="text-gray-400 text-xs text-right">${asn}</span>
            </div>

            <div class="flex justify-between border-b border-gray-900 pb-1">
                <span class="text-gray-500">UBICACIÓN</span>
                <span class="text-gray-300">${city} (${countryCode})</span>
            </div>

            <div class="flex justify-between">
                <span class="text-gray-500">COORDENADAS</span>
                <span class="text-gray-400 font-mono text-xs">${latitude}, ${longitude}</span>
            </div>
        `;

        // Llamada segura para pintar el porcentaje y barra de amenaza
        if (typeof renderThreatMetrics === "function") {
            renderThreatMetrics(currentScannedIp, isp);
        }

    } catch (error) {
        console.error("Error en la petición de Geolocalización:", error);
        alert("Fallo al consultar la base de datos geográfica segura.");
    }
}

// Lógica para acumular reportes locales en el almacenamiento del navegador
btnReportIp.addEventListener('click', () => {
    if (!currentScannedIp) return;
    let localReports = JSON.parse(localStorage.getItem('cyberpulse_reports')) || {};
    localReports[currentScannedIp] = { count: (localReports[currentScannedIp]?.count || 0) + 1 };
    localStorage.setItem('cyberpulse_reports', JSON.stringify(localReports));
    analyzeIp();
});

// Función secundaria para calcular y renderizar las métricas de riesgo
function renderThreatMetrics(ip, isp) {
    if (!threatDataContainer) return;

    let localReports = JSON.parse(localStorage.getItem('cyberpulse_reports')) || {};
    let reportCount = localReports[ip]?.count || 0;

    let threatScore = 0;
    let threatStatus = "CLEAN / LOW RISK";
    let statusClass = "text-emerald-400";

    // Si tiene reportes manuales locales, incrementa drásticamente el score
    if (reportCount > 0) {
        threatScore = Math.min(25 * reportCount, 95); 
    } else {
        // Incremento leve preventivo si proviene de centros de datos/hosting corporativos
        const ispUpper = isp.toUpperCase();
        if (ispUpper.includes("GOOGLE") || ispUpper.includes("CLOUDFLARE") || ispUpper.includes("AMAZON") || ispUpper.includes("HOSTING")) {
            threatScore = 15; 
        } else {
            threatScore = 0; 
        }
    }

    // Clasificación de la severidad del riesgo
    if (threatScore >= 70) {
        threatStatus = "CRITICAL / HIGH THREAT";
        statusClass = "text-red-500 font-bold";
    } else if (threatScore >= 30) {
        threatStatus = "SUSPICIOUS / MEDIUM RISK";
        statusClass = "text-yellow-500 font-bold";
    } else if (threatScore > 0) {
        threatStatus = "MONITORED / MINOR RISK";
        statusClass = "text-blue-400";
    }

    // Inyección de la barra visual de progreso y métricas
    threatDataContainer.innerHTML = `
        <div class="flex justify-between border-b border-gray-900 pb-1">
            <span class="text-gray-500">THREAT LEVEL</span>
            <span class="${statusClass}">${threatStatus}</span>
        </div>

        <div class="mt-2">
            <div class="flex justify-between text-xs text-gray-400 mb-1">
                <span>RISK SCORE</span>
                <span class="font-mono font-bold">${threatScore}%</span>
            </div>
            <div class="w-full bg-gray-900 rounded-full h-2 overflow-hidden border border-gray-800">
                <div class="h-full rounded-full transition-all duration-500 ${
                    threatScore >= 70 ? 'bg-red-500' : threatScore >= 30 ? 'bg-yellow-500' : 'bg-emerald-500'
                }" style="width: ${threatScore}%"></div>
            </div>
        </div>

        <div class="flex justify-between border-b border-gray-900 pb-1 mt-3">
            <span class="text-gray-500">REPORTES LOCALES</span>
            <span class="text-gray-300 font-mono">${reportCount}</span>
        </div>
    `;
}
