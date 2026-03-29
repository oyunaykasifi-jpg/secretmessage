// SecretMessage - Offline, client-side, multilingual
// Single encrypted block: text + optional photo
// Encryption: AES-256-GCM, key derivation: PBKDF2(SHA-256)
// Format: GSM1.<salt>.<iv>.<ct> (Base64URL)

const VERSION = "GSM1";
const PBKDF2_ITERS = 200_000;
const SALT_LEN = 16;
const IV_LEN = 12;

const $ = (id) => document.getElementById(id);

// --------------------------------------------------
// Language detection + translations
// --------------------------------------------------
function detectLang() {
  const htmlLang = (document.documentElement.lang || "").toLowerCase().trim();
  if (htmlLang.startsWith("tr")) return "tr";
  if (htmlLang.startsWith("es")) return "es";
  if (htmlLang.startsWith("pt")) return "pt";
  if (htmlLang.startsWith("fr")) return "fr";
  if (htmlLang.startsWith("de")) return "de";
  if (htmlLang.startsWith("ar")) return "ar";
  return "en";
}

const LANG = detectLang();

const I18N = {
  en: {
    strength: "Strength",
    weak: "Weak",
    medium: "Medium",
    strong: "Strong",
    weakHint: "Use 🔑 Generate or choose a stronger key.",
    mediumHint: "Usable, but a stronger key is better.",
    strongHint: "Great. If possible, share the key outside the same messaging app.",

    invalidFormat: "Invalid format. Expected GSM1.*.*.*",
    invalidPayloadHeader: "Invalid payload header.",
    corruptedHeaderLength: "Corrupted payload header length.",

    keyEmpty: "Key cannot be empty. Use 🔑 Generate if you want.",
    keyEmptyUnlock: "Key cannot be empty.",
    tokenEmpty: "Encrypted block cannot be empty.",
    addMessageOrPhoto: "Add at least a message or a photo.",
    photoLarge: "Warning: The photo is large. The encrypted block may become long. A smaller image may work better.",
    readyLargeBlock: "Ready ✅ Best option for large blocks: send as a document file.",
    copied: "Copied ✅",
    copyFailed: "Could not copy. Clipboard permission may be blocked.",
    shareUnavailableCopied: "Sharing not available. Copied instead ✅",
    readyToShare: "Ready to share ✅",
    shareCancelled: "Share cancelled or failed.",
    fileDownloaded: "File downloaded ✅",
    decrypted: "Decrypted ✅",
    decryptFailedPrefix: "Could not decrypt:",
    textCopied: "Text copied ✅",

    donateCopied: "Copied ✅",
    donateCopyFailed: "Could not copy. Clipboard permission may be blocked.",

    shareTitleCipher: "SecretMessage",
    shareTitlePlain: "Decrypted Message",

    encryptedBlockFile: "encrypted-block.txt",
    decryptedPhotoPrefix: "decrypted-photo"
  },

  tr: {
    strength: "Güç",
    weak: "Zayıf",
    medium: "Orta",
    strong: "Güçlü",
    weakHint: "Daha güçlü bir anahtar için 🔑 Üret seçeneğini kullan.",
    mediumHint: "Kullanılabilir, ama daha güçlü bir anahtar daha iyidir.",
    strongHint: "Harika. Mümkünse anahtarı aynı mesajlaşma uygulamasının dışında paylaş.",

    invalidFormat: "Geçersiz format. Beklenen biçim: GSM1.*.*.*",
    invalidPayloadHeader: "Geçersiz payload başlığı.",
    corruptedHeaderLength: "Bozuk payload başlık uzunluğu.",

    keyEmpty: "Anahtar boş olamaz. İstersen 🔑 Üret kullan.",
    keyEmptyUnlock: "Anahtar boş olamaz.",
    tokenEmpty: "Şifreli blok boş olamaz.",
    addMessageOrPhoto: "En az bir mesaj veya fotoğraf eklemelisin.",
    photoLarge: "Uyarı: Fotoğraf büyük. Şifreli blok uzayabilir. Daha küçük bir görsel daha iyi olabilir.",
    readyLargeBlock: "Hazır ✅ Uzun bloklar için en iyi seçenek: belge veya dosya olarak göndermek.",
    copied: "Kopyalandı ✅",
    copyFailed: "Kopyalanamadı. Pano izni engellenmiş olabilir.",
    shareUnavailableCopied: "Paylaşım kullanılamadı. Bunun yerine kopyalandı ✅",
    readyToShare: "Paylaşıma hazır ✅",
    shareCancelled: "Paylaşım iptal edildi veya başarısız oldu.",
    fileDownloaded: "Dosya indirildi ✅",
    decrypted: "Çözüldü ✅",
    decryptFailedPrefix: "Çözülemedi:",
    textCopied: "Metin kopyalandı ✅",

    donateCopied: "Kopyalandı ✅",
    donateCopyFailed: "Kopyalanamadı. Pano izni engellenmiş olabilir.",

    shareTitleCipher: "SecretMessage",
    shareTitlePlain: "Çözülen Mesaj",

    encryptedBlockFile: "sifreli-blok.txt",
    decryptedPhotoPrefix: "cozulmus-fotograf"
  },

  es: {
    strength: "Seguridad",
    weak: "Débil",
    medium: "Media",
    strong: "Fuerte",
    weakHint: "Usa 🔑 Generar o elige una clave más fuerte.",
    mediumHint: "Sirve, pero una clave más fuerte es mejor.",
    strongHint: "Muy bien. Si es posible, comparte la clave fuera de la misma app de mensajería.",

    invalidFormat: "Formato no válido. Se esperaba GSM1.*.*.*",
    invalidPayloadHeader: "Encabezado de payload no válido.",
    corruptedHeaderLength: "Longitud del encabezado del payload dañada.",

    keyEmpty: "La clave no puede estar vacía. Usa 🔑 Generar si quieres.",
    keyEmptyUnlock: "La clave no puede estar vacía.",
    tokenEmpty: "El bloque cifrado no puede estar vacío.",
    addMessageOrPhoto: "Agrega al menos un mensaje o una foto.",
    photoLarge: "Advertencia: La foto es grande. El bloque cifrado puede hacerse largo. Una imagen más pequeña podría funcionar mejor.",
    readyLargeBlock: "Listo ✅ Para bloques grandes, lo mejor es enviarlos como archivo o documento.",
    copied: "Copiado ✅",
    copyFailed: "No se pudo copiar. El permiso del portapapeles puede estar bloqueado.",
    shareUnavailableCopied: "Compartir no está disponible. Se copió en su lugar ✅",
    readyToShare: "Listo para compartir ✅",
    shareCancelled: "Se canceló el compartir o falló.",
    fileDownloaded: "Archivo descargado ✅",
    decrypted: "Descifrado ✅",
    decryptFailedPrefix: "No se pudo descifrar:",
    textCopied: "Texto copiado ✅",

    donateCopied: "Copiado ✅",
    donateCopyFailed: "No se pudo copiar. El permiso del portapapeles puede estar bloqueado.",

    shareTitleCipher: "SecretMessage",
    shareTitlePlain: "Mensaje descifrado",

    encryptedBlockFile: "bloque-cifrado.txt",
    decryptedPhotoPrefix: "foto-descifrada"
  },

  pt: {
    strength: "Força",
    weak: "Fraca",
    medium: "Média",
    strong: "Forte",
    weakHint: "Use 🔑 Gerar ou escolha uma chave mais forte.",
    mediumHint: "Serve, mas uma chave mais forte é melhor.",
    strongHint: "Ótimo. Se possível, compartilhe a chave fora do mesmo aplicativo de mensagens.",

    invalidFormat: "Formato inválido. Esperado: GSM1.*.*.*",
    invalidPayloadHeader: "Cabeçalho do payload inválido.",
    corruptedHeaderLength: "Comprimento do cabeçalho do payload corrompido.",

    keyEmpty: "A chave não pode estar vazia. Use 🔑 Gerar se quiser.",
    keyEmptyUnlock: "A chave não pode estar vazia.",
    tokenEmpty: "O bloco criptografado não pode estar vazio.",
    addMessageOrPhoto: "Adicione pelo menos uma mensagem ou uma foto.",
    photoLarge: "Aviso: A foto é grande. O bloco criptografado pode ficar longo. Uma imagem menor pode funcionar melhor.",
    readyLargeBlock: "Pronto ✅ Para blocos grandes, a melhor opção é enviar como arquivo ou documento.",
    copied: "Copiado ✅",
    copyFailed: "Não foi possível copiar. A permissão da área de transferência pode estar bloqueada.",
    shareUnavailableCopied: "Compartilhamento indisponível. Foi copiado em vez disso ✅",
    readyToShare: "Pronto para compartilhar ✅",
    shareCancelled: "Compartilhamento cancelado ou falhou.",
    fileDownloaded: "Arquivo baixado ✅",
    decrypted: "Descriptografado ✅",
    decryptFailedPrefix: "Não foi possível descriptografar:",
    textCopied: "Texto copiado ✅",

    donateCopied: "Copiado ✅",
    donateCopyFailed: "Não foi possível copiar. A permissão da área de transferência pode estar bloqueada.",

    shareTitleCipher: "SecretMessage",
    shareTitlePlain: "Mensagem descriptografada",

    encryptedBlockFile: "bloco-criptografado.txt",
    decryptedPhotoPrefix: "foto-descriptografada"
  },

  fr: {
    strength: "Niveau",
    weak: "Faible",
    medium: "Moyen",
    strong: "Fort",
    weakHint: "Utilisez 🔑 Générer ou choisissez une clé plus forte.",
    mediumHint: "Utilisable, mais une clé plus forte est préférable.",
    strongHint: "Parfait. Si possible, partagez la clé en dehors de la même application de messagerie.",

    invalidFormat: "Format invalide. Format attendu : GSM1.*.*.*",
    invalidPayloadHeader: "En-tête de payload invalide.",
    corruptedHeaderLength: "Longueur d’en-tête du payload corrompue.",

    keyEmpty: "La clé ne peut pas être vide. Utilisez 🔑 Générer si vous le souhaitez.",
    keyEmptyUnlock: "La clé ne peut pas être vide.",
    tokenEmpty: "Le bloc chiffré ne peut pas être vide.",
    addMessageOrPhoto: "Ajoutez au moins un message ou une photo.",
    photoLarge: "Avertissement : La photo est grande. Le bloc chiffré peut devenir long. Une image plus petite peut être préférable.",
    readyLargeBlock: "Prêt ✅ Pour les blocs volumineux, le mieux est de les envoyer comme document ou fichier.",
    copied: "Copié ✅",
    copyFailed: "Impossible de copier. L’autorisation du presse-papiers est peut-être bloquée.",
    shareUnavailableCopied: "Partage indisponible. Copié à la place ✅",
    readyToShare: "Prêt à partager ✅",
    shareCancelled: "Partage annulé ou échoué.",
    fileDownloaded: "Fichier téléchargé ✅",
    decrypted: "Déchiffré ✅",
    decryptFailedPrefix: "Impossible de déchiffrer :",
    textCopied: "Texte copié ✅",

    donateCopied: "Copié ✅",
    donateCopyFailed: "Impossible de copier. L’autorisation du presse-papiers est peut-être bloquée.",

    shareTitleCipher: "SecretMessage",
    shareTitlePlain: "Message déchiffré",

    encryptedBlockFile: "bloc-chiffre.txt",
    decryptedPhotoPrefix: "photo-dechiffree"
  },

  de: {
    strength: "Stärke",
    weak: "Schwach",
    medium: "Mittel",
    strong: "Stark",
    weakHint: "Verwende 🔑 Generieren oder wähle einen stärkeren Schlüssel.",
    mediumHint: "Brauchbar, aber ein stärkerer Schlüssel ist besser.",
    strongHint: "Sehr gut. Teile den Schlüssel wenn möglich nicht über dieselbe Messaging-App.",

    invalidFormat: "Ungültiges Format. Erwartet: GSM1.*.*.*",
    invalidPayloadHeader: "Ungültiger Payload-Header.",
    corruptedHeaderLength: "Beschädigte Payload-Header-Länge.",

    keyEmpty: "Der Schlüssel darf nicht leer sein. Nutze bei Bedarf 🔑 Generieren.",
    keyEmptyUnlock: "Der Schlüssel darf nicht leer sein.",
    tokenEmpty: "Der verschlüsselte Block darf nicht leer sein.",
    addMessageOrPhoto: "Füge mindestens eine Nachricht oder ein Foto hinzu.",
    photoLarge: "Warnung: Das Foto ist groß. Der verschlüsselte Block kann lang werden. Ein kleineres Bild könnte besser funktionieren.",
    readyLargeBlock: "Fertig ✅ Für große Blöcke ist das Senden als Datei oder Dokument am besten.",
    copied: "Kopiert ✅",
    copyFailed: "Konnte nicht kopiert werden. Die Zwischenablage-Berechtigung könnte blockiert sein.",
    shareUnavailableCopied: "Teilen nicht verfügbar. Stattdessen kopiert ✅",
    readyToShare: "Bereit zum Teilen ✅",
    shareCancelled: "Teilen abgebrochen oder fehlgeschlagen.",
    fileDownloaded: "Datei heruntergeladen ✅",
    decrypted: "Entschlüsselt ✅",
    decryptFailedPrefix: "Konnte nicht entschlüsseln:",
    textCopied: "Text kopiert ✅",

    donateCopied: "Kopiert ✅",
    donateCopyFailed: "Konnte nicht kopiert werden. Die Zwischenablage-Berechtigung könnte blockiert sein.",

    shareTitleCipher: "SecretMessage",
    shareTitlePlain: "Entschlüsselte Nachricht",

    encryptedBlockFile: "verschluesselter-block.txt",
    decryptedPhotoPrefix: "entschluesseltes-foto"
  },

  ar: {
    strength: "القوة",
    weak: "ضعيفة",
    medium: "متوسطة",
    strong: "قوية",
    weakHint: "استخدم 🔑 إنشاء أو اختر مفتاحًا أقوى.",
    mediumHint: "صالحة للاستخدام، لكن المفتاح الأقوى أفضل.",
    strongHint: "ممتاز. إذا أمكن، شارك المفتاح خارج نفس تطبيق المراسلة.",

    invalidFormat: "تنسيق غير صالح. المتوقع: GSM1.*.*.*",
    invalidPayloadHeader: "رأس الحمولة غير صالح.",
    corruptedHeaderLength: "طول رأس الحمولة تالف.",

    keyEmpty: "لا يمكن أن يكون المفتاح فارغًا. استخدم 🔑 إنشاء إذا أردت.",
    keyEmptyUnlock: "لا يمكن أن يكون المفتاح فارغًا.",
    tokenEmpty: "لا يمكن أن تكون الكتلة المشفرة فارغة.",
    addMessageOrPhoto: "أضف رسالة أو صورة واحدة على الأقل.",
    photoLarge: "تحذير: الصورة كبيرة. قد تصبح الكتلة المشفرة طويلة. قد تكون الصورة الأصغر أفضل.",
    readyLargeBlock: "جاهز ✅ للكتل الكبيرة، الخيار الأفضل هو الإرسال كملف أو مستند.",
    copied: "تم النسخ ✅",
    copyFailed: "تعذر النسخ. قد يكون إذن الحافظة محظورًا.",
    shareUnavailableCopied: "المشاركة غير متاحة. تم النسخ بدلًا من ذلك ✅",
    readyToShare: "جاهز للمشاركة ✅",
    shareCancelled: "تم إلغاء المشاركة أو فشلت.",
    fileDownloaded: "تم تنزيل الملف ✅",
    decrypted: "تم فك التشفير ✅",
    decryptFailedPrefix: "تعذر فك التشفير:",
    textCopied: "تم نسخ النص ✅",

    donateCopied: "تم النسخ ✅",
    donateCopyFailed: "تعذر النسخ. قد يكون إذن الحافظة محظورًا.",

    shareTitleCipher: "SecretMessage",
    shareTitlePlain: "الرسالة المفككة",

    encryptedBlockFile: "encrypted-block.txt",
    decryptedPhotoPrefix: "decrypted-photo"
  }
};

const T = I18N[LANG] || I18N.en;

// --------------------------------------------------
// Encoding helpers
// --------------------------------------------------
function b64urlEncode(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlDecode(str) {
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  const b64 = (str + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toUtf8Bytes(s) {
  return new TextEncoder().encode(s);
}

function fromUtf8Bytes(b) {
  return new TextDecoder().decode(b);
}

// --------------------------------------------------
// Crypto
// --------------------------------------------------
async function deriveKeyFromPass(pass, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    toUtf8Bytes(pass),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptBytes(plainBytes, pass) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKeyFromPass(pass, salt);

  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plainBytes);
  const ct = new Uint8Array(ctBuf);

  return `${VERSION}.${b64urlEncode(salt)}.${b64urlEncode(iv)}.${b64urlEncode(ct)}`;
}

async function decryptBytes(token, pass) {
  const parts = token.trim().split(".");
  if (parts.length !== 4 || parts[0] !== VERSION) {
    throw new Error(T.invalidFormat);
  }

  const salt = b64urlDecode(parts[1]);
  const iv = b64urlDecode(parts[2]);
  const ct = b64urlDecode(parts[3]);

  const key = await deriveKeyFromPass(pass, salt);
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);

  return new Uint8Array(ptBuf);
}

// --------------------------------------------------
// Payload packaging
// --------------------------------------------------
function u32ToBytesLE(n) {
  const a = new Uint8Array(4);
  const dv = new DataView(a.buffer);
  dv.setUint32(0, n, true);
  return a;
}

function bytesToU32LE(b, off) {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(off, true);
}

function concatBytes(...arrs) {
  const total = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
}

async function buildPayload(plainText, photoFile) {
  const header = { t: plainText || "" };

  let photoBytes = null;
  if (photoFile) {
    const buf = await photoFile.arrayBuffer();
    photoBytes = new Uint8Array(buf);
    header.p = {
      mime: photoFile.type || "application/octet-stream",
      len: photoBytes.length,
    };
  }

  const hdrBytes = toUtf8Bytes(JSON.stringify(header));
  const magic = toUtf8Bytes("PK1");
  const hdrLen = u32ToBytesLE(hdrBytes.length);

  return photoBytes
    ? concatBytes(magic, hdrLen, hdrBytes, photoBytes)
    : concatBytes(magic, hdrLen, hdrBytes);
}

function parsePayload(payloadBytes) {
  const magic = fromUtf8Bytes(payloadBytes.slice(0, 3));
  if (magic !== "PK1") throw new Error(T.invalidPayloadHeader);

  const hdrLen = bytesToU32LE(payloadBytes, 3);
  const hdrStart = 7;
  const hdrEnd = hdrStart + hdrLen;

  if (hdrEnd > payloadBytes.length) throw new Error(T.corruptedHeaderLength);

  const hdr = JSON.parse(fromUtf8Bytes(payloadBytes.slice(hdrStart, hdrEnd)));
  const photo = hdr.p ? payloadBytes.slice(hdrEnd, hdrEnd + hdr.p.len) : null;

  return {
    text: hdr.t || "",
    photoMime: hdr.p?.mime || null,
    photoBytes: photo
  };
}

// --------------------------------------------------
// Short readable key generator
// --------------------------------------------------
const WORDS_BY_LANG = {
  en: ["ocean", "river", "forest", "sun", "moon", "ember", "meadow", "cloud", "night", "star", "stone", "valley", "wind", "shore", "echo", "spark", "field", "cedar", "dawn", "mist"],
  tr: ["mavi", "deniz", "orman", "gunes", "ay", "kivilcim", "bulut", "gece", "yildiz", "tas", "vadi", "ruzgar", "sahil", "nehir", "cayir", "dag", "doga", "marti", "sabah", "sis"],
  es: ["mar", "rio", "bosque", "sol", "luna", "chispa", "nube", "noche", "estrella", "piedra", "valle", "viento", "orilla", "eco", "campo", "cedro", "amanecer", "bruma", "fuego", "monte"],
  pt: ["mar", "rio", "floresta", "sol", "lua", "faísca", "nuvem", "noite", "estrela", "pedra", "vale", "vento", "costa", "eco", "campo", "cedro", "aurora", "névoa", "fogo", "monte"],
  fr: ["mer", "riviere", "foret", "soleil", "lune", "etincelle", "nuage", "nuit", "etoile", "pierre", "vallee", "vent", "rive", "echo", "champ", "cedre", "aube", "brume", "flamme", "mont"],
  de: ["meer", "fluss", "wald", "sonne", "mond", "funke", "wolke", "nacht", "stern", "stein", "tal", "wind", "ufer", "echo", "feld", "zeder", "morgen", "nebel", "glut", "berg"],
  ar: ["bahr", "nahr", "ghaba", "shams", "qamar", "sharara", "sahab", "layl", "najm", "hajar", "wadi", "rih", "sahil", "sada", "haql", "arz", "fajr", "dabab", "nar", "jabal"]
};

function randInt(max) {
  return crypto.getRandomValues(new Uint32Array(1))[0] % max;
}

function cap(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function genShortKey() {
  const words = WORDS_BY_LANG[LANG] || WORDS_BY_LANG.en;
  const w1 = words[randInt(words.length)];
  const w2 = words[randInt(words.length)];
  const n = String(randInt(100)).padStart(2, "0");
  const letters = "abcdefghjkmnpqrstuvwxyz";
  const l1 = letters[randInt(letters.length)];
  const l2 = letters[randInt(letters.length)];
  return `${cap(w1)}${cap(w2)}${n}${l1}${l2}`;
}

function estimateStrength(key) {
  const k = (key || "").trim();
  if (!k) return { level: "-", cls: "", hint: "" };

  let score = 0;
  if (k.length >= 8) score += 1;
  if (k.length >= 12) score += 1;
  if (/[a-z]/.test(k)) score += 1;
  if (/[A-Z]/.test(k)) score += 1;
  if (/[0-9]/.test(k)) score += 1;
  if (/[^a-zA-Z0-9]/.test(k)) score += 1;

  if (k.length < 8 || score <= 2) {
    return {
      level: T.weak,
      cls: "err",
      hint: T.weakHint
    };
  }

  if (score <= 4) {
    return {
      level: T.medium,
      cls: "warn",
      hint: T.mediumHint
    };
  }

  return {
    level: T.strong,
    cls: "ok",
    hint: T.strongHint
  };
}

// --------------------------------------------------
// UI helpers
// --------------------------------------------------
function setTab(isLock) {
  $("panelLock").style.display = isLock ? "block" : "none";
  $("panelUnlock").style.display = isLock ? "none" : "block";
  $("tabLock").classList.toggle("primary", isLock);
  $("tabUnlock").classList.toggle("primary", !isLock);
}

function updateStrengthUI() {
  const el = $("key");
  if (!el) return;
  const s = estimateStrength(el.value);
  $("strengthPill").textContent = `${T.strength}: ${s.level}`;
  $("strengthPill").className = `pill ${s.cls || ""}`;
  $("strengthHint").textContent = s.hint || "";
}

async function copyToClipboard(text) {
  await navigator.clipboard.writeText(text);
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

function downloadBlob(filename, blob) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

function extFromMime(mime) {
  const m = (mime || "").toLowerCase();
  if (m.includes("png")) return "png";
  if (m.includes("jpeg") || m.includes("jpg")) return "jpg";
  if (m.includes("webp")) return "webp";
  if (m.includes("gif")) return "gif";
  return "bin";
}

async function shareText(title, text) {
  if (navigator.share) {
    await navigator.share({ title, text });
    return true;
  }
  return false;
}

let lastImgBlob = null;
let lastImgUrl = null;
let lastImgMime = null;

// Register root SW so subfolders also work correctly
function registerSW() {
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }
}

// --------------------------------------------------
// Events
// --------------------------------------------------
$("tabLock").onclick = () => setTab(true);
$("tabUnlock").onclick = () => setTab(false);

$("genKey").onclick = () => {
  $("key").value = genShortKey();
  updateStrengthUI();
};

$("key").addEventListener("input", updateStrengthUI);

$("lockBtn").onclick = async () => {
  try {
    $("lockStatus").textContent = "";

    const text = $("plain").value || "";
    const file = $("photo").files?.[0] || null;
    const key = $("key").value.trim();

    if (!key) {
      $("lockStatus").textContent = T.keyEmpty;
      return;
    }

    if (!text.trim() && !file) {
      $("lockStatus").textContent = T.addMessageOrPhoto;
      return;
    }

    if (file && file.size > 800_000) {
      $("lockStatus").textContent = T.photoLarge;
    }

    const payload = await buildPayload(text, file);
    const token = await encryptBytes(payload, key);

    $("cipher").value = token;
    $("lockStatus").textContent = T.readyLargeBlock;
  } catch (e) {
    $("lockStatus").textContent = `Error: ${e.message || e}`;
  }
};

$("copyCipher").onclick = async () => {
  const t = $("cipher").value.trim();
  if (!t) return;

  try {
    await copyToClipboard(t);
    $("lockStatus").textContent = T.copied;
  } catch {
    $("lockStatus").textContent = T.copyFailed;
  }
};

const shareCipherBtn = document.getElementById("shareCipher");
if (shareCipherBtn) {
  shareCipherBtn.onclick = async () => {
    const t = $("cipher").value.trim();
    if (!t) return;

    try {
      const ok = await shareText(T.shareTitleCipher, t);
      if (!ok) {
        await copyToClipboard(t);
        $("lockStatus").textContent = T.shareUnavailableCopied;
      } else {
        $("lockStatus").textContent = T.readyToShare;
      }
    } catch {
      $("lockStatus").textContent = T.shareCancelled;
    }
  };
}

$("downloadCipher").onclick = () => {
  const t = $("cipher").value.trim();
  if (!t) return;

  downloadText(T.encryptedBlockFile, t);
  $("lockStatus").textContent = T.fileDownloaded;
};

$("clearLock").onclick = () => {
  $("plain").value = "";
  $("photo").value = "";
  $("cipher").value = "";
  $("lockStatus").textContent = "";
};

$("unlockBtn").onclick = async () => {
  try {
    $("unlockStatus").textContent = "";
    $("plainOut").value = "";
    $("imgWrap").style.display = "none";
    lastImgBlob = null;
    lastImgMime = null;

    if (lastImgUrl) {
      URL.revokeObjectURL(lastImgUrl);
      lastImgUrl = null;
    }

    const token = $("cipherIn").value.trim();
    const key = $("keyIn").value.trim();

    if (!token) {
      $("unlockStatus").textContent = T.tokenEmpty;
      return;
    }

    if (!key) {
      $("unlockStatus").textContent = T.keyEmptyUnlock;
      return;
    }

    const payloadBytes = await decryptBytes(token, key);
    const parsed = parsePayload(payloadBytes);

    $("plainOut").value = parsed.text || "";

    if (parsed.photoBytes && parsed.photoMime) {
      lastImgMime = parsed.photoMime;
      lastImgBlob = new Blob([parsed.photoBytes], { type: parsed.photoMime });
      lastImgUrl = URL.createObjectURL(lastImgBlob);
      $("imgOut").src = lastImgUrl;
      $("imgWrap").style.display = "block";
    }

    $("unlockStatus").textContent = T.decrypted;
  } catch (e) {
    $("unlockStatus").textContent = `${T.decryptFailedPrefix} ${e.message || e}`;
  }
};

$("downloadImg").onclick = () => {
  if (!lastImgBlob) return;
  const ext = extFromMime(lastImgMime);
  downloadBlob(`${T.decryptedPhotoPrefix}.${ext}`, lastImgBlob);
};

$("copyPlain").onclick = async () => {
  const t = $("plainOut").value.trim();
  if (!t) return;

  try {
    await copyToClipboard(t);
    $("unlockStatus").textContent = T.textCopied;
  } catch {
    $("unlockStatus").textContent = T.copyFailed;
  }
};

const sharePlainBtn = document.getElementById("sharePlain");
if (sharePlainBtn) {
  sharePlainBtn.onclick = async () => {
    const t = $("plainOut").value.trim();
    if (!t) return;

    try {
      const ok = await shareText(T.shareTitlePlain, t);
      if (!ok) {
        await copyToClipboard(t);
        $("unlockStatus").textContent = T.shareUnavailableCopied;
      } else {
        $("unlockStatus").textContent = T.readyToShare;
      }
    } catch {
      $("unlockStatus").textContent = T.shareCancelled;
    }
  };
}

$("clearUnlock").onclick = () => {
  $("cipherIn").value = "";
  $("keyIn").value = "";
  $("plainOut").value = "";
  $("imgWrap").style.display = "none";
  $("unlockStatus").textContent = "";

  if (lastImgUrl) {
    URL.revokeObjectURL(lastImgUrl);
    lastImgUrl = null;
  }

  lastImgBlob = null;
  lastImgMime = null;
};

// Donate copy
const donateBtn = document.getElementById("copyDonate");
if (donateBtn) {
  donateBtn.onclick = async () => {
    try {
      const addr = document.getElementById("donateAddr").value;
      await navigator.clipboard.writeText(addr);
      document.getElementById("donateStatus").textContent = T.donateCopied;
    } catch {
      document.getElementById("donateStatus").textContent = T.donateCopyFailed;
    }
  };
}

function toggleHow() {
  const box = document.getElementById("howBox");
  box.style.display = box.style.display === "none" ? "block" : "none";
}

// init
updateStrengthUI();
registerSW();
