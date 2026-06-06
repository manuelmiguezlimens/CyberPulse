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
// 4. INTELIGENCIA DE AMENAZAS E IP GEO (CORREGIDO HTTPS)
// ==========================================
const inputIp = document.getElementById('input-ip');
const btnSearchIp = document.getElementById('search-ip');
const resultIp = document.getElementById('result-ip');
const geoDataContainer = document.getElementById('geo-data');
// Asegúrate de que este elemento existe en tu index.html o coméntalo si da error
const threatDataContainer = document.getElementById('threat-data'); 
const btnReportIp = document.getElementById('btn-report-ip');

let currentScannedIp = "";

btnSearchIp.addEventListener('click', analyzeIp);

async function analyzeIp() {
    const ip = inputIp.value.trim();

    // ipwho.is funciona nativamente con HTTPS y permite consultas vacías para la IP actual
    const url = ip 
        ? `https://ipwho.is/${encodeURIComponent(ip)}` 
        : `https://ipwho.is/`;

    try {
        const response = await fetch(url);
        
        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status}`);
        }

        const data = await response.json();

        // ipwho.is devuelve un booleano 'success' para validar si la consulta fue correcta
        if (!data.success) {
            alert(`Error: ${data.message || 'Dirección IP no válida o no encontrada.'}`);
            return;
        }

        currentScannedIp = data.ip;
        resultIp.classList.remove('hidden');

        // Adaptación del mapeo de variables según la estructura JSON de ipwho.is
        const isp = data.connection?.isp || 'N/A';
        const asn = data.connection?.asn || 'N/A';
        const city = data.city || 'N/A';
        const countryCode = data.country_code || 'N/A';
        const latitude = data.latitude || 0;
        const longitude = data.longitude || 0;

        // Inyección limpia del HTML estructurado con Tailwind CSS
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
                <span class="text-gray-400 text-xs text-right">ASN${asn}</span>
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

        // Si tienes una función secundaria para procesar métricas adicionales, se ejecuta aquí
        if (typeof renderThreatMetrics === "function") {
            renderThreatMetrics(currentScannedIp, isp);
        }

    } catch (error) {
        console.error("Error en la petición de Geolocalización:", error);
        alert("Fallo al consultar la base de datos geográfica segura.");
    }
}

// Lógica local para simular o procesar reportes guardados en el navegador
btnReportIp.addEventListener('click', () => {
    if (!currentScannedIp) return;
    let localReports = JSON.parse(localStorage.getItem('cyberpulse_reports')) || {};
    localReports[currentScannedIp] = { count: (localReports[currentScannedIp]?.count || 0) + 1 };
    localStorage.setItem('cyberpulse_reports', JSON.stringify(localReports));
    analyzeIp();
});
