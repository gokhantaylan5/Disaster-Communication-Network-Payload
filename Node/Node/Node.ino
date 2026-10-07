#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <SPI.h>
#include <LoRa.h>
#include <esp_wifi.h>
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"

// Toggle these depending on field test results
#define LORA_MODE_FAST
// #define LORA_MODE_RANGE

// --- Hardware Setup ---
#define LORA_SS    5
#define LORA_RST   14
#define LORA_DIO0  2
#define STATUS_LED 2   // Onboard LED for heartbeat/status

// --- Network & Crypto ---
#define LORA_FREQ    433E6
#define DRONE_ID     "DRN-01"
const char* AP_NAME  = "EMERGENCY_NETWORK";
const char* AES_KEY  = "EmergencyNet2026";  // Must be exactly 16 chars for AES-128

// --- System Limits ---
#define MAX_LOG_SIZE   80000
#define MAX_MSG_LEN    80
#define MAX_NAME_LEN   30
#define ACK_TIMEOUT    3000   // ms
#define MAX_RETRY      3
#define RATE_LIMIT_MS  1000   // throttle to 1 msg/sec per user
#define MAX_PENDING    8      // max packets waiting for ACK

// --- Filesystem ---
const char* FILE_MSG = "/messages.txt";
const char* FILE_BAN = "/banned.txt";

const byte DNS_PORT = 53;
DNSServer dnsServer;
WebServer server(80);
bool loraActive = false;

// --- Packet State ---
uint32_t pktCount = 0;

struct PendingPacket {
  uint32_t seqNum;
  String payload;
  unsigned long txTime;
  int retries;
  bool active;
};
PendingPacket txQueue[MAX_PENDING];

// Simple ring buffer to drop duplicate rx packets
uint32_t rxHistory[16];
int rxHistoryIdx = 0;

// --- Rate Limiting ---
struct RateLimit {
  String uid;
  unsigned long lastTx;
};
RateLimit userLimits[10];

// --- Telemetry / Stats ---
unsigned long bootTime = 0;
uint32_t statsTx = 0;
uint32_t statsRx = 0;
uint32_t statsDropped = 0;
int lastRSSI = 0;
float lastSNR = 0;
unsigned long lastAckTime = 0;

// --- AES-128 CBC ---
String encryptAES_CBC(String plainText) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, (const unsigned char*)AES_KEY, 128);

  // PKCS#7 Padding
  int origLen = plainText.length();
  int padLen  = origLen + (16 - (origLen % 16));
  unsigned char input[padLen];
  unsigned char output[padLen];
  unsigned char iv[16];
  unsigned char ivCopy[16];

  // Generate random IV
  for (int i = 0; i < 16; i++) {
    iv[i] = (unsigned char)esp_random();
    ivCopy[i] = iv[i]; // keep a copy since mbedtls modifies it
  }

  plainText.getBytes(input, origLen + 1);
  int padVal = padLen - origLen;
  for (int i = origLen; i < padLen; i++) input[i] = padVal;

  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padLen, ivCopy, input, output);
  mbedtls_aes_free(&aes);

  // Prepend IV to ciphertext
  int totalLen = 16 + padLen;
  unsigned char combined[totalLen];
  memcpy(combined, iv, 16);
  memcpy(combined + 16, output, padLen);

  size_t b64Len = 0;
  size_t outBufLen = ((totalLen + 2) / 3) * 4 + 1;
  unsigned char b64Out[outBufLen];
  mbedtls_base64_encode(b64Out, outBufLen, &b64Len, combined, totalLen);

  String result = "";
  for (size_t i = 0; i < b64Len; i++) result += (char)b64Out[i];
  return result;
}

String decryptAES_CBC(String b64Input) {
  b64Input.trim();
  if (b64Input.length() < 24) return ""; // too short to be valid

  size_t decLen = 0;
  size_t inLen = b64Input.length();
  unsigned char decoded[inLen + 1];
  int ret = mbedtls_base64_decode(decoded, inLen, &decLen,
                                   (const unsigned char*)b64Input.c_str(), inLen);
  
  if (ret != 0 || decLen < 32 || (decLen - 16) % 16 != 0) return "";

  // Extract IV
  unsigned char iv[16];
  memcpy(iv, decoded, 16);

  int cipherLen = decLen - 16;
  unsigned char input[cipherLen];
  unsigned char output[cipherLen];
  memcpy(input, decoded + 16, cipherLen);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, (const unsigned char*)AES_KEY, 128);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, cipherLen, iv, input, output);
  mbedtls_aes_free(&aes);

  // Strip padding
  int padVal = output[cipherLen - 1];
  if (padVal < 1 || padVal > 16) return ""; 
  int plainLen = cipherLen - padVal;

  String result = "";
  for (int i = 0; i < plainLen; i++) result += (char)output[i];
  return result;
}

// --- Helpers ---
String splitString(String data, char sep, int idx) {
  int found = 0;
  int strIndex[] = { 0, -1 };
  int maxIndex = data.length() - 1;
  for (int i = 0; i <= maxIndex && found <= idx; i++) {
    if (data.charAt(i) == sep || i == maxIndex) {
      found++;
      strIndex[0] = strIndex[1] + 1;
      strIndex[1] = (i == maxIndex) ? i + 1 : i;
    }
  }
  return found > idx ? data.substring(strIndex[0], strIndex[1]) : "";
}

String cleanInput(String s, int maxLen) {
  // basic sanitization to prevent breaking the delimiter format or html
  s.replace("\n", " ");
  s.replace("\r", " ");
  s.replace("|", "-");
  s.replace(":", "-");
  s.replace("<", "&lt;");
  s.replace(">", "&gt;");
  s.replace("\"", "'");
  s.trim();
  if ((int)s.length() > maxLen) s = s.substring(0, maxLen);
  return s;
}

// --- Auth & Identification ---
String getUserId() {
  if (server.hasHeader("Cookie")) {
    String cookie = server.header("Cookie");
    int idx = cookie.indexOf("UID=");
    if (idx != -1) {
      int endIdx = cookie.indexOf(';', idx);
      if (endIdx == -1) endIdx = cookie.length();
      return cookie.substring(idx + 4, endIdx);
    }
  }
  return "";
}

String generateUID() {
  // grab last octet of IP + random int. decent enough for field usage
  String ip = server.client().remoteIP().toString();
  int dot = ip.lastIndexOf('.');
  String suffix = ip.substring(dot + 1);
  return "EMR-" + suffix + String(random(100, 999));
}

int getClientRSSI() {
  // hacky way to estimate user distance via WiFi signal strength
  wifi_sta_list_t staList;
  if (esp_wifi_ap_get_sta_list(&staList) == ESP_OK && staList.num > 0) {
    int best = -100;
    for (int i = 0; i < staList.num; i++) {
      if (staList.sta[i].rssi > best) best = staList.sta[i].rssi;
    }
    return best;
  }
  return -90;
}

// --- Ban System ---
bool isBanned(String uid) {
  if (uid == "") return false;
  File f = LittleFS.open(FILE_BAN, FILE_READ);
  if (!f) return false;
  
  bool banned = false;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line == uid) { banned = true; break; }
  }
  f.close();
  return banned;
}

void banUser(String uid) {
  File f = LittleFS.open(FILE_BAN, FILE_APPEND);
  if (f) { f.println(uid); f.close(); }
}

bool hasActiveSession(String uid) {
  if (uid == "" || isBanned(uid)) return false;
  File f = LittleFS.open(FILE_MSG, FILE_READ);
  if (!f) return false;
  
  bool found = false;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.startsWith(uid + "|") || line.startsWith("CENTER|" + uid + "|")) {
      found = true;
      break;
    }
  }
  f.close();
  return found;
}

// --- Anti-Spam ---
bool checkRateLimit(String uid) {
  unsigned long now = millis();
  for (int i = 0; i < 10; i++) {
    if (userLimits[i].uid == uid) {
      if (now - userLimits[i].lastTx < RATE_LIMIT_MS) return false;
      userLimits[i].lastTx = now;
      return true;
    }
  }
  // No entry found, grab an empty or stale slot
  for (int i = 0; i < 10; i++) {
    if (userLimits[i].uid == "" || (now - userLimits[i].lastTx > 60000)) {
      userLimits[i].uid = uid;
      userLimits[i].lastTx = now;
      return true;
    }
  }
  return true; 
}

// --- LoRa Core ---
void txLoRa(String payload, bool requireAck) {
  if (!loraActive) return;
  
  pktCount++;
  String rawPacket = "DATA:" + String(pktCount) + ":" + DRONE_ID + ":" + payload;
  String cipher = encryptAES_CBC(rawPacket);

  LoRa.beginPacket();
  LoRa.print(cipher);
  LoRa.endPacket();
  statsTx++;
  
  Serial.printf("[TX] #%d (%dB)\n", pktCount, cipher.length());

  if (requireAck) {
    for (int i = 0; i < MAX_PENDING; i++) {
      if (!txQueue[i].active) {
        txQueue[i].seqNum = pktCount;
        txQueue[i].payload = payload;
        txQueue[i].txTime = millis();
        txQueue[i].retries = 0;
        txQueue[i].active = true;
        break;
      }
    }
  }
}

void txAck(uint32_t seqNum) {
  if (!loraActive) return;
  String ackMsg = "ACK:" + String(seqNum) + ":" + DRONE_ID;
  String cipher = encryptAES_CBC(ackMsg);
  
  LoRa.beginPacket();
  LoRa.print(cipher);
  LoRa.endPacket();
}

void processAckTimeouts() {
  unsigned long now = millis();
  for (int i = 0; i < MAX_PENDING; i++) {
    if (!txQueue[i].active) continue;
    
    // Exponential backoff for retries
    unsigned long timeout = ACK_TIMEOUT * (1 << txQueue[i].retries);
    
    if (now - txQueue[i].txTime > timeout) {
      if (txQueue[i].retries < MAX_RETRY) {
        txQueue[i].retries++;
        
        String rawPacket = "DATA:" + String(txQueue[i].seqNum) + ":" + DRONE_ID + ":" + txQueue[i].payload;
        String cipher = encryptAES_CBC(rawPacket);
        
        LoRa.beginPacket();
        LoRa.print(cipher);
        LoRa.endPacket();
        
        txQueue[i].txTime = now;
        Serial.printf("[RETRY] %d/%d for #%d\n", txQueue[i].retries, MAX_RETRY, txQueue[i].seqNum);
      } else {
        Serial.printf("[DROP] Dead packet #%d\n", txQueue[i].seqNum);
        txQueue[i].active = false;
        statsDropped++;
      }
    }
  }
}

bool checkDuplicateRx(uint32_t seqNum) {
  for (int i = 0; i < 16; i++) {
    if (rxHistory[i] == seqNum) return true;
  }
  rxHistory[rxHistoryIdx] = seqNum;
  rxHistoryIdx = (rxHistoryIdx + 1) % 16;
  return false;
}

void rotateLogs() {
  File f = LittleFS.open(FILE_MSG, FILE_READ);
  if (!f) return;
  
  size_t fileSize = f.size();
  f.close();
  
  // Cut file in half if it gets too bloated
  if (fileSize > MAX_LOG_SIZE) {
    Serial.println("[FS] Log rotation triggered");
    File reader = LittleFS.open(FILE_MSG, FILE_READ);
    File temp = LittleFS.open("/tmp_rot.txt", FILE_WRITE);
    
    if (reader && temp) {
      reader.seek(fileSize / 2);
      reader.readStringUntil('\n'); // align to next full line
      while (reader.available()) {
        temp.println(reader.readStringUntil('\n'));
      }
      reader.close(); 
      temp.close();
      LittleFS.remove(FILE_MSG);
      LittleFS.rename("/tmp_rot.txt", FILE_MSG);
    }
  }
}

// --- Web UI ---
const char htmlForm[] PROGMEM = R"HTML(
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Emergency Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:linear-gradient(135deg,#c0392b,#e74c3c);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:15px}
.card{background:#fff;border-radius:16px;padding:25px;width:100%;max-width:420px;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.logo{text-align:center;margin-bottom:20px}
.logo h1{color:#c0392b;font-size:24px;margin-bottom:5px}
.logo p{color:#666;font-size:13px}
.alert{background:#fff3cd;border-left:4px solid #f39c12;padding:12px;border-radius:6px;font-size:12px;color:#664d03;margin-bottom:20px;line-height:1.5}
label{display:block;font-size:12px;font-weight:600;color:#444;margin-bottom:5px;margin-top:12px}
input,select,textarea{width:100%;padding:12px;border:2px solid #e0e0e0;border-radius:8px;font-size:15px;font-family:inherit;transition:border .2s}
input:focus,select:focus,textarea:focus{outline:0;border-color:#e74c3c}
textarea{resize:vertical;min-height:60px}
.counter{font-size:11px;color:#999;text-align:right;margin-top:3px}
button{width:100%;padding:15px;background:#c0392b;color:#fff;border:0;border-radius:8px;font-size:16px;font-weight:700;cursor:pointer;margin-top:20px;transition:background .2s}
button:hover{background:#a93226}
button:disabled{background:#aaa;cursor:not-allowed}
.row{display:flex;gap:10px}
.row>div{flex:1}
.hint{font-size:10px;color:#888;margin-top:3px}
</style></head><body>
<div class="card">
<div class="logo"><h1>🆘 EMERGENCY</h1><p>Direct link to Rescue Teams</p></div>
<div class="alert">📡 Your location is estimated via WiFi signal strength. Do not turn off your phone.</div>
<form id="f" action="/submit" method="POST">
<input type="hidden" name="t" id="t">
<input type="hidden" name="d" id="d">
<label>👤 Full Name</label>
<input type="text" name="name" required maxlength="30" placeholder="e.g., John Doe">
<div class="row">
<div><label>🩺 Status</label>
<select name="status" required>
<option value="" disabled selected>Select...</option>
<option value="Trapped">🚨 Trapped</option>
<option value="Injured">🤕 Injured</option>
<option value="Safe">✅ Safe</option>
</select></div>
<div><label>👥 People with you</label>
<input type="number" name="people" required min="0" max="999" value="0">
<div class="hint">Type 0 if alone</div></div>
</div>
<label>💬 Short Note (optional)</label>
<textarea name="msg" maxlength="80" placeholder="e.g., No water, pinned by debris..."></textarea>
<div class="counter"><span id="c">0</span>/80</div>
<button type="submit" id="btn">📤 Request Help</button>
</form></div>
<script>
function pad(n){return String(n).padStart(2,'0')}
const ta=document.querySelector('textarea');
ta.oninput=()=>document.getElementById('c').textContent=ta.value.length;
document.getElementById('f').onsubmit=()=>{
  const dt=new Date();
  document.getElementById('t').value=pad(dt.getHours())+':'+pad(dt.getMinutes())+':'+pad(dt.getSeconds());
  document.getElementById('d').value=pad(dt.getDate())+'.'+pad(dt.getMonth()+1)+'.'+dt.getFullYear();
  document.getElementById('btn').disabled=true;
  document.getElementById('btn').textContent='Sending...';
};
</script></body></html>
)HTML";

const char htmlChat[] PROGMEM = R"HTML(
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rescue Link</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#075e54;height:100vh;display:flex;flex-direction:column}
.header{background:#054c44;color:#fff;padding:12px 15px;display:flex;align-items:center;gap:12px;box-shadow:0 2px 4px rgba(0,0,0,.2)}
.avatar{width:40px;height:40px;border-radius:50%;background:#25d366;display:flex;align-items:center;justify-content:center;font-size:20px}
.info{flex:1}
.info .name{font-weight:600;font-size:15px}
.info .stat{font-size:11px;opacity:.8;display:flex;align-items:center;gap:5px}
.dot{width:8px;height:8px;border-radius:50%;background:#25d366;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.chat{flex:1;overflow-y:auto;padding:15px;background:#e5ddd5;display:flex;flex-direction:column;gap:8px}
.msg{padding:8px 12px;border-radius:8px;font-size:14px;max-width:75%;word-wrap:break-word;box-shadow:0 1px 1px rgba(0,0,0,.1);position:relative}
.msg.me{background:#dcf8c6;align-self:flex-end;border-bottom-right-radius:0}
.msg.them{background:#fff;align-self:flex-start;border-bottom-left-radius:0}
.msg.bc{background:#fff3cd;align-self:center;text-align:center;font-weight:600;border:1px solid #ffe69c;max-width:90%}
.msg .from{font-size:10px;font-weight:600;color:#075e54;margin-bottom:2px}
.msg .time{font-size:9px;color:#888;display:block;margin-top:4px;text-align:right}
.input{background:#f0f0f0;padding:10px;display:flex;gap:8px}
.input input{flex:1;padding:12px 15px;border:0;border-radius:25px;font-size:14px;outline:0;background:#fff}
.input input:disabled{opacity:.5}
.input button{padding:12px 20px;background:#25d366;color:#fff;border:0;border-radius:50%;cursor:pointer;font-size:16px;width:48px;height:48px}
.input button:disabled{background:#aaa;cursor:wait}
.empty{text-align:center;color:#888;font-size:13px;padding:20px}
</style></head><body>
<div class="header">
<div class="avatar">🚁</div>
<div class="info"><div class="name">Command Center</div>
<div class="stat"><span class="dot"></span> Connection stable • Tracking</div></div>
</div>
<div class="chat" id="chat"><div class="empty">Loading...</div></div>
<div class="input">
<input id="mi" placeholder="Type a message..." maxlength="80">
<button id="sbtn" onclick="send()">➤</button>
</div>
<script>
let lastHash='';
let sending=false;
function pad(n){return String(n).padStart(2,'0')}
function nowTime(){const d=new Date();return pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds())}
function nowDate(){const d=new Date();return pad(d.getDate())+'.'+pad(d.getMonth()+1)+'.'+d.getFullYear()}

async function load(){
  try{
    const r=await fetch('/api/msgs');
    if(r.status===403){location.href='/';return}
    const d=await r.json();
    if(!d.ok){location.href='/';return}
    const h=JSON.stringify(d.msgs);
    if(h===lastHash)return;
    lastHash=h;
    const c=document.getElementById('chat');
    if(d.msgs.length===0){c.innerHTML='<div class="empty">No messages yet.</div>';return}
    c.innerHTML=d.msgs.map(m=>{
      const ts=`${m.date||''} ${m.time||''}`.trim();
      if(m.type==='broadcast')return `<div class="msg bc">📢 ${m.text}<span class="time">${ts}</span></div>`;
      if(m.type==='center')return `<div class="msg them"><div class="from">Command Center</div>${m.text}<span class="time">${ts}</span></div>`;
      return `<div class="msg me">${m.text}<span class="time">${ts}</span></div>`;
    }).join('');
    c.scrollTop=c.scrollHeight;
  }catch(e){console.error(e)}
}

async function send(){
  if(sending)return;
  const i=document.getElementById('mi');
  const b=document.getElementById('sbtn');
  const m=i.value.trim();
  if(!m)return;
  sending=true;
  i.disabled=true;b.disabled=true;
  const t=nowTime();const d=nowDate();
  try{
    const r=await fetch('/api/send',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:`msg=${encodeURIComponent(m)}&t=${t}&d=${d}`});
    if(r.status===403){location.href='/';return}
    if(r.status===429){alert('Throttled. Please wait a moment.');sending=false;i.disabled=false;b.disabled=false;return}
    i.value='';
    await load();
  }catch(e){console.error(e)}
  sending=false;
  i.disabled=false;b.disabled=false;
  i.focus();
}

document.getElementById('mi').onkeypress=e=>{if(e.key==='Enter'&&!sending)send()};
load();
setInterval(load,1500);
</script></body></html>
)HTML";

// --- HTTP Handlers ---
void handleRoot() {
  String uid = getUserId();

  if (uid == "" || isBanned(uid)) {
    uid = generateUID();
    server.sendHeader("Set-Cookie", "UID=" + uid + "; Path=/; Max-Age=31536000");
    Serial.println("[HTTP] Assigned new UID: " + uid);
    server.send_P(200, "text/html", htmlForm);
    return;
  }

  if (!hasActiveSession(uid)) {
    server.send_P(200, "text/html", htmlForm);
  } else {
    // Already filled out the form, dump them straight to chat
    server.sendHeader("Location", "/chat");
    server.send(303);
  }
}

void handleChat() {
  String uid = getUserId();
  if (!hasActiveSession(uid) || isBanned(uid)) {
    server.sendHeader("Location", "/");
    server.send(303);
    return;
  }
  server.send_P(200, "text/html", htmlChat);
}

void handleSubmit() {
  if (!server.hasArg("name") || !server.hasArg("status")) {
    server.send(400, "text/plain", "Missing args");
    return;
  }

  String uid = getUserId();
  if (uid == "" || isBanned(uid)) {
    uid = generateUID();
    server.sendHeader("Set-Cookie", "UID=" + uid + "; Path=/; Max-Age=31536000");
  }

  String name = cleanInput(server.arg("name"), MAX_NAME_LEN);
  String status = server.arg("status");
  String peopleCount = server.arg("people");
  String rssiStr = String(getClientRSSI());
  String txTime = server.hasArg("t") && server.arg("t") != "" ? server.arg("t") : "00:00:00";
  String txDate = server.hasArg("d") ? server.arg("d") : "";
  String note = cleanInput(server.arg("msg"), MAX_MSG_LEN);
  
  if (note == "") note = "(no note)";
  if (peopleCount == "") peopleCount = "0";

  if (status != "Trapped" && status != "Injured" && status != "Safe") {
    server.send(400, "text/plain", "Invalid status");
    return;
  }

  // Schema: id|name|status|people|lat|lon|rssi|time|msg|date
  String payload = uid + "|" + name + "|" + status + "|" + peopleCount + "|0|0|" + rssiStr + "|" + txTime + "|" + note + "|" + txDate;
  
  File f = LittleFS.open(FILE_MSG, FILE_APPEND);
  if (f) { f.println(payload); f.close(); }

  txLoRa(payload, true);
  rotateLogs();

  server.sendHeader("Location", "/chat");
  server.send(303);
}

void handleApiSend() {
  if (!server.hasArg("msg")) { server.send(400, "text/plain", "Missing args"); return; }

  String uid = getUserId();
  if (uid == "" || isBanned(uid)) { server.send(403, "text/plain", "DENIED"); return; }
  if (!checkRateLimit(uid)) { server.send(429, "text/plain", "RATELIMIT"); return; }

  String note = cleanInput(server.arg("msg"), MAX_MSG_LEN);
  String txTime = server.hasArg("t") ? server.arg("t") : "00:00:00";
  String txDate = server.hasArg("d") ? server.arg("d") : "";
  
  if (note == "") { server.send(400, "text/plain", "Empty"); return; }

  String name = "", status = "", peopleCount = "";
  bool found = false;
  
  // Scrape user's existing details from logs
  File f = LittleFS.open(FILE_MSG, FILE_READ);
  if (f) {
    while (f.available()) {
      String line = f.readStringUntil('\n');
      line.trim();
      if (line.startsWith(uid + "|")) {
        found = true;
        name = splitString(line, '|', 1);
        status = splitString(line, '|', 2);
        peopleCount = splitString(line, '|', 3);
      }
    }
    f.close();
  }

  if (!found) { server.send(403, "text/plain", "DENIED"); return; }

  String rssiStr = String(getClientRSSI());
  String payload = uid + "|" + name + "|" + status + "|" + peopleCount + "|0|0|" + rssiStr + "|" + txTime + "|" + note + "|" + txDate;

  File wf = LittleFS.open(FILE_MSG, FILE_APPEND);
  if (wf) { wf.println(payload); wf.close(); }

  txLoRa(payload, true);
  rotateLogs();
  
  server.send(200, "application/json", "{\"ok\":true}");
}

void handleApiMsgs() {
  String uid = getUserId();
  if (uid == "" || isBanned(uid) || !hasActiveSession(uid)) {
    server.send(403, "application/json", "{\"ok\":false}");
    return;
  }

  String jsonResponse = "{\"ok\":true,\"msgs\":[";
  bool isFirst = true;
  
  File f = LittleFS.open(FILE_MSG, FILE_READ);
  if (f) {
    while (f.available()) {
      String line = f.readStringUntil('\n');
      line.trim();
      if (line.length() == 0) continue;

      String msgType = "", text = "", timeStr = "", dateStr = "";
      
      if (line.startsWith("CENTER|" + uid + "|")) {
        // Schema: CENTER|<uid>|<time>|<msg>|<date>
        msgType = "center";
        timeStr = splitString(line, '|', 2);
        text = splitString(line, '|', 3);
        dateStr = splitString(line, '|', 4);
      } 
      else if (line.startsWith("BROADCAST|")) {
        // Schema: BROADCAST|<no>|<time>|<text>|<date>
        msgType = "broadcast";
        timeStr = splitString(line, '|', 2);
        text = splitString(line, '|', 3);
        dateStr = splitString(line, '|', 4);
      } 
      else if (line.startsWith(uid + "|")) {
        // Schema: uid|name|status|people|lat|lon|rssi|time|msg|date
        msgType = "me";
        timeStr = splitString(line, '|', 7);
        text = splitString(line, '|', 8);
        dateStr = splitString(line, '|', 9);
      } 
      else continue; // ignore other users' messages

      if (!isFirst) jsonResponse += ",";
      isFirst = false;
      
      jsonResponse += "{\"type\":\"" + msgType + "\",\"time\":\"" + timeStr +
                      "\",\"date\":\"" + dateStr + "\",\"text\":\"" + text + "\"}";
    }
    f.close();
  }
  jsonResponse += "]}";
  server.send(200, "application/json", jsonResponse);
}

void handleHealth() {
  // Simple diagnostic endpoint for dashboard
  String json = "{";
  json += "\"id\":\"" + String(DRONE_ID) + "\",";
  json += "\"uptime\":" + String((millis() - bootTime) / 1000) + ",";
  json += "\"lora\":" + String(loraActive ? "true" : "false") + ",";
  json += "\"sent\":" + String(statsTx) + ",";
  json += "\"recv\":" + String(statsRx) + ",";
  json += "\"dropped\":" + String(statsDropped) + ",";
  json += "\"rssi\":" + String(lastRSSI) + ",";
  json += "\"snr\":" + String(lastSNR, 1) + ",";
  json += "\"fs_used\":" + String(LittleFS.usedBytes()) + ",";
  json += "\"fs_total\":" + String(LittleFS.totalBytes());
  json += "}";
  server.send(200, "application/json", json);
}

// --- LoRa Receive ---
void handleLoRaRx(String rxDecrypted) {
  if (rxDecrypted.startsWith("ACK:")) {
    int colon1 = 4;
    int colon2 = rxDecrypted.indexOf(':', colon1);
    if (colon2 == -1) return;
    
    uint32_t ackSeq = rxDecrypted.substring(colon1, colon2).toInt();
    
    for (int i = 0; i < MAX_PENDING; i++) {
      if (txQueue[i].active && txQueue[i].seqNum == ackSeq) {
        txQueue[i].active = false; // flag as delivered
        lastAckTime = millis();
        Serial.printf("[ACK] #%d OK\n", ackSeq);
        return;
      }
    }
  } 
  else if (rxDecrypted.startsWith("DATA:")) {
    int colon1 = 5;
    int colon2 = rxDecrypted.indexOf(':', colon1);
    int colon3 = rxDecrypted.indexOf(':', colon2 + 1);
    if (colon2 == -1 || colon3 == -1) return;
    
    uint32_t seq = rxDecrypted.substring(colon1, colon2).toInt();
    String payload = rxDecrypted.substring(colon3 + 1);

    if (checkDuplicateRx(seq)) { 
      txAck(seq); // already seen it, just resend ack
      return; 
    }
    
    txAck(seq);
    statsRx++;

    // Command parser
    if (payload.startsWith("SYS_CMD|CLEAR_BC|")) {
      String bcID = payload.substring(17); 
      bcID.trim();
      Serial.println("[CMD] Pruning broadcast: " + bcID);
      
      File tmp = LittleFS.open("/tmp.txt", FILE_WRITE);
      File f = LittleFS.open(FILE_MSG, FILE_READ);
      if (f && tmp) {
        while (f.available()) {
          String line = f.readStringUntil('\n');
          line.trim();
          if (line.length() == 0) continue;
          if (line.startsWith("BROADCAST|" + bcID + "|")) continue;
          tmp.println(line);
        }
        f.close(); tmp.close();
        LittleFS.remove(FILE_MSG);
        LittleFS.rename("/tmp.txt", FILE_MSG);
      }
      return;
    }

    if (payload.startsWith("SYS_CMD|CLEAR_USER|")) {
      String targetUid = payload.substring(19); 
      targetUid.trim();
      Serial.println("[CMD] Scrubbing user data: " + targetUid);
      
      File tmp = LittleFS.open("/tmp.txt", FILE_WRITE);
      File f = LittleFS.open(FILE_MSG, FILE_READ);
      if (f && tmp) {
        while (f.available()) {
          String line = f.readStringUntil('\n');
          line.trim();
          if (line.length() == 0) continue;
          if (!line.startsWith(targetUid + "|") && !line.startsWith("CENTER|" + targetUid + "|")) {
            tmp.println(line);
          }
        }
        f.close(); tmp.close();
        LittleFS.remove(FILE_MSG);
        LittleFS.rename("/tmp.txt", FILE_MSG);
      }
      banUser(targetUid);
      
    } else if (payload == "SYS_CMD|CLEAR") {
      Serial.println("[CMD] NUKING FILESYSTEM");
      LittleFS.remove(FILE_MSG);
      LittleFS.remove(FILE_BAN);
      
    } else {
      // Normal message, append to log
      File f = LittleFS.open(FILE_MSG, FILE_APPEND);
      if (f) { f.println(payload); f.close(); }
    }
  }
}

void blinkStatus(int count, int delayMs) {
  for (int i = 0; i < count; i++) {
    digitalWrite(STATUS_LED, HIGH);
    delay(delayMs);
    digitalWrite(STATUS_LED, LOW);
    delay(delayMs);
  }
}

// --- Init ---
void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n--- DRONE NODE BOOT ---");

  pinMode(STATUS_LED, OUTPUT);
  blinkStatus(3, 100);

  bootTime = millis();
  randomSeed(esp_random());

  // Zero out structs
  for (int i = 0; i < MAX_PENDING; i++) txQueue[i].active = false;
  for (int i = 0; i < 16; i++) rxHistory[i] = 0;
  for (int i = 0; i < 10; i++) { userLimits[i].uid = ""; userLimits[i].lastTx = 0; }

  if (!LittleFS.begin(true)) {
    Serial.println("[FS] Mount failed");
  } else {
    Serial.println("[FS] Mounted");
  }

  // WiFi - Force 802.11b because it has significantly better wall penetration & range
  WiFi.mode(WIFI_AP);
  esp_wifi_set_protocol(WIFI_IF_AP, WIFI_PROTOCOL_11B);
  WiFi.softAP(AP_NAME, NULL, 6);
  WiFi.setTxPower(WIFI_POWER_19_5dBm);
  
  dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
  Serial.printf("[WiFi] AP: %s @ %s [802.11b Only]\n", AP_NAME, WiFi.softAPIP().toString().c_str());

  const char* headerKeys[] = {"Cookie"};
  server.collectHeaders(headerKeys, 1);

  // Bind endpoints
  server.on("/", HTTP_GET, handleRoot);
  server.on("/chat", HTTP_GET, handleChat);
  server.on("/submit", HTTP_POST, handleSubmit);
  server.on("/api/send", HTTP_POST, handleApiSend);
  server.on("/api/msgs", HTTP_GET, handleApiMsgs);
  server.on("/health", HTTP_GET, handleHealth);

  // Aggressive Captive Portal routing (catch all common OS checks)
  server.on("/generate_204", HTTP_GET, handleRoot);
  server.on("/gen_204", HTTP_GET, handleRoot);
  server.on("/hotspot-detect.html", HTTP_GET, handleRoot);
  server.on("/library/test/success.html", HTTP_GET, handleRoot);
  server.on("/ncsi.txt", HTTP_GET, handleRoot);
  server.on("/connecttest.txt", HTTP_GET, handleRoot);
  server.on("/redirect", HTTP_GET, handleRoot);
  server.on("/success.txt", HTTP_GET, handleRoot);
  server.onNotFound(handleRoot);

  server.begin();
  Serial.println("[HTTP] Webserver active");

  // LoRa Init
  LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);
  if (!LoRa.begin(LORA_FREQ)) {
    loraActive = false;
    Serial.println("[LoRa] Init FAIL - Check wiring!");
    blinkStatus(10, 50);
  } else {
    loraActive = true;
    LoRa.setTxPower(20); // Push Ra-02 module to max output (20dBm)
    
    #ifdef LORA_MODE_FAST
      LoRa.setSpreadingFactor(7);     // SF7 = fast but lower range
      LoRa.setSignalBandwidth(250E3); // 250kHz for decent throughput
      LoRa.setCodingRate4(5);         // CR4/5 = less overhead
      Serial.println("[LoRa] Config: FAST (SF7, BW250, CR4/5, 20dBm)");
    #else
      LoRa.setSpreadingFactor(10);    // SF10 = deep penetration/range
      LoRa.setSignalBandwidth(125E3); // 125kHz = narrow band
      LoRa.setCodingRate4(8);         // CR4/8 = max redundancy/error correction
      Serial.println("[LoRa] Config: RANGE (SF10, BW125, CR4/8, 20dBm)");
    #endif
    
    LoRa.setPreambleLength(8);
    LoRa.setSyncWord(0xF3); // Keep this matching on ground station
    LoRa.enableCrc();
  }

  digitalWrite(STATUS_LED, HIGH);  // Solid LED means init passed
  Serial.println("--- READY ---\n");
}

// --- Main Loop ---
unsigned long tickTime = 0;
bool ledFlag = true;

void loop() {
  // Feed the captive portal and webserver
  dnsServer.processNextRequest();
  server.handleClient();

  // Lazy heartbeat (blink every 2s)
  if (millis() - tickTime > 2000) {
    tickTime = millis();
    ledFlag = !ledFlag;
    digitalWrite(STATUS_LED, ledFlag);
  }

  // Poll for incoming LoRa frames
  if (loraActive) {
    int packetSize = LoRa.parsePacket();
    if (packetSize) {
      String rawRx = "";
      while (LoRa.available()) rawRx += (char)LoRa.read();
      
      lastRSSI = LoRa.packetRssi();
      lastSNR = LoRa.packetSnr();
      
      String plainTxt = decryptAES_CBC(rawRx);
      if (plainTxt != "") {
        Serial.printf("[RX] RSSI: %d | SNR: %.1f\n", lastRSSI, lastSNR);
        handleLoRaRx(plainTxt);
      } else {
        Serial.println("[RX] Decrypt failed (bad key or corrupted block)");
      }
    }
  }

  // Sweep the queue for dead/unacked packets
  processAckTimeouts();
  
  yield();
  delay(1); // prevent WDT crash
}