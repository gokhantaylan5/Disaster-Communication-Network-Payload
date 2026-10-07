#include <WiFi.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <SPI.h>
#include <LoRa.h>
#include <esp_wifi.h>
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"

// ============ LORA SPEED PROFILE ============
// This must match the Drone exactly
#define LORA_MODE_FAST
// #define LORA_MODE_RANGE

// ============ HARDWARE PINS ============
#define LORA_SS    5
#define LORA_RST   14
#define LORA_DIO0  2
#define STATUS_LED 2

// ============ NETWORK CONFIG ============
#define LORA_FREQ    433E6
#define BASE_ID      "BASE-01"
const char* AP_NAME      = "SEARCH_RESCUE_BASE";
const char* WIFI_PASS    = "base2026";
const char* PANEL_PASS   = "rescue2026";
const char* AES_KEY      = "RescueNetKey2026"; // Must be exactly 16 chars

// ============ SYSTEM LIMITS ============
#define MAX_LOG_SIZE      150000
#define MAX_MSG_LEN       100
#define ACK_TIMEOUT       2000
#define MAX_RETRY         3
#define MAX_PENDING       8
#define LOGIN_LOCK_TIME   300000 // 5 minutes
#define LOGIN_MAX_ATTEMPT 5

const char* LOG_FILE = "/log.txt";

WebServer server(80);
bool isLoraActive = false;

uint32_t packetCounter = 0;
struct PendingPacket {
  uint32_t packetNo;
  String data;
  unsigned long sendTime;
  int retryCount;
  bool active;
};

PendingPacket pendingPackets[MAX_PENDING];
uint32_t lastReceivedPackets[16];
int lastReceivedIndex = 0;

int failedAttempts = 0;
unsigned long lockUntil = 0;

unsigned long bootTime = 0;
uint32_t totalTx = 0;
uint32_t totalRx = 0;
uint32_t totalFail = 0;
int lastRSSI = 0;
float lastSNR = 0;
uint32_t broadcastCounter = 0;

// ============ AES-128 CBC ENCRYPTION ============
String encryptAES_CBC(String plainText) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, (const unsigned char*)AES_KEY, 128);

  int origLen = plainText.length();
  int padLen = origLen + (16 - (origLen % 16));
  unsigned char input[padLen];
  unsigned char output[padLen];
  unsigned char iv[16];
  unsigned char ivCopy[16];

  // Generate a random Initialization Vector (IV)
  for (int i = 0; i < 16; i++) {
    iv[i] = (unsigned char)esp_random();
    ivCopy[i] = iv[i];
  }

  plainText.getBytes(input, origLen + 1);
  int padVal = padLen - origLen;
  for (int i = origLen; i < padLen; i++) input[i] = padVal;

  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padLen, ivCopy, input, output);
  mbedtls_aes_free(&aes);

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
  if (b64Input.length() < 24) return "";

  size_t decLen = 0;
  size_t inLen = b64Input.length();
  unsigned char decoded[inLen + 1];
  int ret = mbedtls_base64_decode(decoded, inLen, &decLen,
                                   (const unsigned char*)b64Input.c_str(), inLen);
  
  // Basic validation to avoid crashes on garbage data
  if (ret != 0 || decLen < 32 || (decLen - 16) % 16 != 0) return "";

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

  int padVal = output[cipherLen - 1];
  if (padVal < 1 || padVal > 16) return "";
  int plainLen = cipherLen - padVal;

  String result = "";
  for (int i = 0; i < plainLen; i++) result += (char)output[i];
  return result;
}

// Helper: Split string by delimiter and get specific index
String getValue(String data, char sep, int idx) {
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

// Clean up user inputs so they don't break our parser
String sanitize(String s, int maxLen) {
  s.replace("\n", " ");
  s.replace("\r", " ");
  s.replace("|", "-");
  s.replace(":", "-");
  s.replace("\"", "'");
  s.trim();
  if ((int)s.length() > maxLen) s = s.substring(0, maxLen);
  return s;
}

String jsonEscape(String s) {
  s.replace("\\", "\\\\");
  s.replace("\"", "\\\"");
  s.replace("\n", " ");
  s.replace("\r", " ");
  return s;
}

void loraSend(String data, bool waitForAck) {
  if (!isLoraActive) return;
  
  packetCounter++;
  String packet = "DATA:" + String(packetCounter) + ":" + BASE_ID + ":" + data;
  String encrypted = encryptAES_CBC(packet);

  LoRa.beginPacket();
  LoRa.print(encrypted);
  LoRa.endPacket();
  
  totalTx++;
  Serial.println("[TX] #" + String(packetCounter) + " (" + String(encrypted.length()) + "B)");

  // Throw it into the pending queue if we need an acknowledgment
  if (waitForAck) {
    for (int i = 0; i < MAX_PENDING; i++) {
      if (!pendingPackets[i].active) {
        pendingPackets[i].packetNo = packetCounter;
        pendingPackets[i].data = data;
        pendingPackets[i].sendTime = millis();
        pendingPackets[i].retryCount = 0;
        pendingPackets[i].active = true;
        break;
      }
    }
  }
}

void loraSendAck(uint32_t no) {
  if (!isLoraActive) return;
  String ackMsg = "ACK:" + String(no) + ":" + BASE_ID;
  String encrypted = encryptAES_CBC(ackMsg);
  
  LoRa.beginPacket();
  LoRa.print(encrypted);
  LoRa.endPacket();
}

// Check if any packet needs to be re-transmitted
void ackTimeoutCheck() {
  unsigned long now = millis();
  for (int i = 0; i < MAX_PENDING; i++) {
    if (!pendingPackets[i].active) continue;
    
    unsigned long timeout = ACK_TIMEOUT * (1 << pendingPackets[i].retryCount); // Exponential backoff
    
    if (now - pendingPackets[i].sendTime > timeout) {
      if (pendingPackets[i].retryCount < MAX_RETRY) {
        pendingPackets[i].retryCount++;
        String packet = "DATA:" + String(pendingPackets[i].packetNo) + ":" +
                        BASE_ID + ":" + pendingPackets[i].data;
        String encrypted = encryptAES_CBC(packet);
        
        LoRa.beginPacket();
        LoRa.print(encrypted);
        LoRa.endPacket();
        
        pendingPackets[i].sendTime = now;
        Serial.println("[RETRY] " + String(pendingPackets[i].retryCount) +
                       "/" + String(MAX_RETRY));
      } else {
        // Gave up on this packet
        Serial.println("[FAIL] #" + String(pendingPackets[i].packetNo));
        File f = LittleFS.open(LOG_FILE, FILE_APPEND);
        if (f) { f.println("FAIL|" + String(pendingPackets[i].packetNo)); f.close(); }
        pendingPackets[i].active = false;
        totalFail++;
      }
    }
  }
}

// Prevent processing the same packet twice
bool isDuplicate(uint32_t no) {
  for (int i = 0; i < 16; i++) if (lastReceivedPackets[i] == no) return true;
  lastReceivedPackets[lastReceivedIndex] = no;
  lastReceivedIndex = (lastReceivedIndex + 1) % 16;
  return false;
}

// Keep the log file from eating all our flash memory
void logRotation() {
  File f = LittleFS.open(LOG_FILE, FILE_READ);
  if (!f) return;
  size_t size = f.size();
  f.close();
  
  if (size > MAX_LOG_SIZE) {
    File reader = LittleFS.open(LOG_FILE, FILE_READ);
    File tempFile = LittleFS.open("/tmp_rot.txt", FILE_WRITE);
    if (reader && tempFile) {
      reader.seek(size / 2);
      reader.readStringUntil('\n'); // Skip the cut-off line
      while (reader.available()) tempFile.println(reader.readStringUntil('\n'));
      reader.close(); tempFile.close();
      LittleFS.remove(LOG_FILE);
      LittleFS.rename("/tmp_rot.txt", LOG_FILE);
    }
  }
}

// ============ HTML LOGIN ============
const char login_html[] PROGMEM = R"HTML(
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Command Center Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#1a252f;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#2c3e50;border-radius:16px;padding:40px;width:100%;max-width:400px;box-shadow:0 20px 60px rgba(0,0,0,.5);border-top:4px solid #e74c3c}
.logo{text-align:center;margin-bottom:30px}
.logo h1{color:#e74c3c;font-size:28px;letter-spacing:1px}
.logo p{color:#95a5a6;font-size:13px;margin-top:5px}
.alert{padding:12px;border-radius:6px;font-size:13px;margin-bottom:20px;display:none}
.alert.err{background:#c0392b}
.alert.lock{background:#e67e22}
.alert.show{display:block}
label{display:block;font-size:12px;color:#bdc3c7;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px}
input{width:100%;padding:14px;background:#34495e;border:2px solid #34495e;border-radius:8px;color:#fff;font-size:15px;transition:border .2s}
input:focus{outline:0;border-color:#e74c3c}
button{width:100%;padding:15px;background:#e74c3c;color:#fff;border:0;border-radius:8px;font-size:15px;font-weight:700;cursor:pointer;margin-top:20px;text-transform:uppercase;letter-spacing:1px;transition:background .2s}
button:hover{background:#c0392b}
button:disabled{background:#7f8c8d;cursor:not-allowed}
</style></head><body>
<div class="card">
<div class="logo"><h1>🚁 COMMAND CENTER</h1><p>Search & Rescue System</p></div>
<div id="errBox" class="alert err">⚠️ Invalid password!</div>
<div id="lockBox" class="alert lock">🔒 Too many failed attempts. Please wait 5 minutes.</div>
<form action="/login" method="POST">
<label>Admin Password</label>
<input type="password" name="pwd" required autofocus placeholder="••••••••">
<button type="submit" id="btn">Login</button>
</form></div>
<script>
(function(){
  // Only show warnings if the URL actually has ?e=1 or ?e=lock
  const params=new URLSearchParams(window.location.search);
  const errCode=params.get('e');
  if(errCode==='1'){
    document.getElementById('errBox').classList.add('show');
  } else if(errCode==='lock'){
    document.getElementById('lockBox').classList.add('show');
    document.getElementById('btn').disabled=true;
  }
  // Clean up the URL so the error message doesn't pop up again on refresh
  if(errCode){
    setTimeout(()=>{
      window.history.replaceState({},document.title,window.location.pathname);
    },100);
  }
})();
</script></body></html>
)HTML";

// ============ HTML DASHBOARD ============
const char dashboard_html[] PROGMEM = R"HTML(
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Command Center Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#1a252f;color:#ecf0f1;height:100vh;display:flex;flex-direction:column;overflow:hidden}
.topbar{background:#2c3e50;padding:12px 20px;display:flex;align-items:center;gap:20px;border-bottom:3px solid #e74c3c;flex-shrink:0}
.topbar h1{color:#e74c3c;font-size:18px;letter-spacing:1px}
.topbar .stats{display:flex;gap:15px;margin-left:auto;font-size:12px}
.stat{background:#34495e;padding:6px 12px;border-radius:6px}
.stat .lbl{color:#95a5a6;font-size:10px;text-transform:uppercase}
.stat .val{color:#fff;font-weight:600;font-size:14px}
.stat.ok .val{color:#2ecc71}
.stat.warn .val{color:#f39c12}
.stat.err .val{color:#e74c3c}
.btns{display:flex;gap:8px}
.btns button{padding:8px 14px;border:0;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600}
.b-bc{background:#f39c12;color:#fff}
.b-rst{background:#c0392b;color:#fff}
.b-out{background:#34495e;color:#fff}
.b-exp{background:#16a085;color:#fff}
.main{flex:1;display:grid;grid-template-columns:280px 1fr 340px;gap:10px;padding:10px;overflow:hidden}
.panel{background:#2c3e50;border-radius:10px;overflow:hidden;display:flex;flex-direction:column}
.ph{padding:12px 15px;background:#34495e;font-size:13px;font-weight:600;display:flex;justify-content:space-between;align-items:center}
.ph .badge{background:#e74c3c;color:#fff;padding:2px 8px;border-radius:10px;font-size:11px}
.search{padding:10px 12px;background:#34495e;border-bottom:1px solid #2c3e50}
.search input{width:100%;padding:8px 12px;background:#2c3e50;border:1px solid #34495e;border-radius:6px;color:#fff;font-size:13px}
.filters{padding:8px 12px;display:flex;gap:5px;background:#34495e;border-bottom:1px solid #2c3e50}
.filters button{flex:1;padding:5px;background:#2c3e50;border:0;border-radius:4px;color:#bdc3c7;font-size:11px;cursor:pointer}
.filters button.act{background:#e74c3c;color:#fff}
.users{flex:1;overflow-y:auto;padding:8px}
.user{background:#34495e;padding:10px 12px;border-radius:8px;margin-bottom:6px;cursor:pointer;border-left:4px solid #7f8c8d;transition:all .2s}
.user:hover{background:#3d566e}
.user.act{background:#3d566e;border-left-color:#e74c3c}
.user.trapped{border-left-color:#c0392b}
.user.injured{border-left-color:#f39c12}
.user.safe{border-left-color:#27ae60}
.user .un{font-weight:600;font-size:13px;display:flex;justify-content:space-between;align-items:center}
.user .ud{font-size:11px;color:#bdc3c7;margin-top:3px}
.user .ud .pri{padding:1px 6px;border-radius:3px;font-size:10px;margin-right:5px}
.user .ud .pri.trapped{background:#c0392b;color:#fff}
.user .ud .pri.injured{background:#f39c12;color:#fff}
.user .ud .pri.safe{background:#27ae60;color:#fff}
.user .um{font-size:11px;color:#95a5a6;margin-top:4px;font-style:italic}
.chat-wrap{display:flex;flex-direction:column;overflow:hidden}
.chat-head{padding:12px 15px;background:#34495e;display:flex;justify-content:space-between;align-items:center}
.chat-head .who{font-weight:600;font-size:14px}
.chat-head .who .det{font-size:11px;color:#95a5a6;margin-top:2px;font-weight:400}
.chat-head .acts{display:flex;gap:6px}
.chat-head button{padding:6px 10px;background:#c0392b;color:#fff;border:0;border-radius:4px;cursor:pointer;font-size:11px}
.msgs{flex:1;overflow-y:auto;padding:15px;background:#1a252f;display:flex;flex-direction:column;gap:8px}
.msg{padding:8px 12px;border-radius:8px;max-width:75%;font-size:13px;word-wrap:break-word}
.msg.in{background:#34495e;align-self:flex-start;border-bottom-left-radius:0}
.msg.out{background:#16a085;align-self:flex-end;border-bottom-right-radius:0}
.msg.fail{background:#7f3c3c;align-self:center;font-size:11px;font-style:italic}
.msg .h{font-size:10px;opacity:.8;margin-bottom:3px;font-weight:600}
.msg .t{font-size:9px;opacity:.6;display:block;margin-top:4px;text-align:right}
.qrep{padding:8px 12px;background:#34495e;display:flex;gap:5px;flex-wrap:wrap;border-top:1px solid #2c3e50}
.qrep button{padding:5px 10px;background:#2c3e50;border:1px solid #16a085;color:#16a085;border-radius:14px;cursor:pointer;font-size:11px;transition:all .2s}
.qrep button:hover:not(:disabled){background:#16a085;color:#fff}
.qrep button:disabled{opacity:.4;cursor:wait}
.sender{padding:10px;background:#34495e;display:flex;gap:8px}
.sender input{flex:1;padding:10px;background:#2c3e50;border:0;border-radius:6px;color:#fff;font-size:13px}
.sender input:disabled{opacity:.5}
.sender button{padding:10px 18px;background:#16a085;color:#fff;border:0;border-radius:6px;cursor:pointer;font-weight:600}
.sender button:disabled{background:#7f8c8d;cursor:wait}
.empty{text-align:center;color:#7f8c8d;padding:30px 15px;font-size:13px}
.scroll-btn{position:absolute;bottom:120px;right:30px;background:#16a085;color:#fff;border:0;border-radius:20px;padding:8px 14px;font-size:12px;font-weight:600;cursor:pointer;box-shadow:0 4px 12px rgba(0,0,0,.4);display:none;z-index:10;animation:bounce 1s infinite}
.scroll-btn.show{display:block}
@keyframes bounce{0%,100%{transform:translateY(0)}50%{transform:translateY(-3px)}}
.chat-wrap{position:relative}
.right-wrap{display:flex;flex-direction:column;overflow:hidden}
.radar-box{padding:12px;display:flex;flex-direction:column;align-items:center;background:#2c3e50;border-bottom:1px solid #34495e}
.radar-box canvas{background:#1a252f;border-radius:50%;border:2px solid #34495e}
.radar-box .info{margin-top:10px;font-size:11px;text-align:center;line-height:1.5}
.bc-section{flex:1;display:flex;flex-direction:column;overflow:hidden}
.bc-list{flex:1;overflow-y:auto;padding:8px}
.bc-item{background:#3a3522;border-left:3px solid #f39c12;padding:8px 10px;border-radius:6px;margin-bottom:6px;font-size:12px;position:relative}
.bc-item .bc-text{color:#ffe69c;word-wrap:break-word;padding-right:25px}
.bc-item .bc-meta{color:#95a5a6;font-size:10px;margin-top:4px;display:flex;justify-content:space-between}
.bc-item .bc-del{position:absolute;top:6px;right:6px;background:none;border:0;color:#e74c3c;cursor:pointer;font-size:14px;padding:2px 6px;border-radius:3px}
.bc-item .bc-del:hover{background:#c0392b;color:#fff}
.sys-info{padding:10px 12px;background:#34495e;border-top:1px solid #2c3e50;font-size:11px;line-height:1.6}
.sys-info .row{display:flex;justify-content:space-between;color:#bdc3c7}
.sys-info .row b{color:#fff}
.modal{display:none;position:fixed;z-index:1000;left:0;top:0;width:100%;height:100%;background:rgba(0,0,0,.75);align-items:center;justify-content:center}
.modal.show{display:flex}
.modal-c{background:#2c3e50;padding:25px;border-radius:10px;width:90%;max-width:500px;border-top:3px solid #f39c12}
.modal-c h3{margin-bottom:15px;color:#f39c12}
.modal-c textarea{width:100%;height:80px;padding:10px;background:#34495e;border:1px solid #34495e;color:#fff;border-radius:6px;font-size:13px;resize:vertical;font-family:inherit}
.modal-btns{display:flex;gap:10px;margin-top:15px;justify-content:flex-end}
.modal-btns button{padding:10px 20px;border:0;border-radius:6px;cursor:pointer;font-weight:600}
.btn-c{background:#7f8c8d;color:#fff}
.btn-g{background:#f39c12;color:#fff}
.toast{position:fixed;bottom:20px;right:20px;background:#16a085;color:#fff;padding:12px 20px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,.3);z-index:2000;display:none}
.toast.show{display:block;animation:slideIn .3s}
@keyframes slideIn{from{transform:translateX(100%)}to{transform:translateX(0)}}
</style></head><body>

<div class="topbar">
<h1>🚁 COMMAND CENTER</h1>
<div class="stats">
<div class="stat" id="sLora"><div class="lbl">LoRa</div><div class="val">-</div></div>
<div class="stat" id="sUsers"><div class="lbl">Survivors</div><div class="val">0</div></div>
<div class="stat" id="sCrit"><div class="lbl">Critical</div><div class="val">0</div></div>
<div class="stat" id="sUp"><div class="lbl">Uptime</div><div class="val">00:00:00</div></div>
</div>
<div class="btns">
<button class="b-bc" onclick="openBc()">📢 Broadcast</button>
<button class="b-exp" onclick="exp()">💾 Export</button>
<button class="b-rst" onclick="rst()">⚠️ Reset</button>
<button class="b-out" onclick="location.href='/logout'">Logout</button>
</div>
</div>

<div class="main">
  <div class="panel">
    <div class="ph">Survivors <span class="badge" id="userCnt">0</span></div>
    <div class="search"><input id="srch" placeholder="🔍 Search by name..." oninput="render()"></div>
    <div class="filters">
      <button class="act" data-f="all" onclick="setF('all')">All</button>
      <button data-f="trapped" onclick="setF('trapped')">Trapped</button>
      <button data-f="injured" onclick="setF('injured')">Injured</button>
      <button data-f="safe" onclick="setF('safe')">Safe</button>
    </div>
    <div class="users" id="users"></div>
  </div>

  <div class="panel chat-wrap">
    <div class="chat-head">
      <div class="who" id="who">Select a survivor...</div>
      <div class="acts"><button id="kbtn" style="display:none" onclick="kick()">Kick from System</button></div>
    </div>
  <div class="msgs" id="msgs"><div class="empty">Select a survivor from the left panel</div></div>
    <button class="scroll-btn" id="scrollBtn" onclick="scrollBottom()">⬇ New Message</button>
    <div class="qrep" id="qrep" style="display:none">
      <button onclick="qm(this,'We spotted you, hold on')">Hold On</button>
      <button onclick="qm(this,'Teams are deployed')">Teams on way</button>
      <button onclick="qm(this,'Help will arrive in 30 mins')">30 mins</button>
      <button onclick="qm(this,'Bringing water and oxygen')">Water/O2</button>
      <button onclick="qm(this,'Try to make some noise')">Make noise</button>
    </div>
    <div class="sender">
      <input id="mi" placeholder="Type a message..." maxlength="100" disabled>
      <button id="sbtn" onclick="snd()" disabled>SEND ➤</button>
    </div>
  </div>

  <div class="panel right-wrap">
    <div class="ph">🎯 Location Tracking</div>
    <div class="radar-box">
      <canvas id="rdr" width="200" height="200"></canvas>
      <div class="info" id="rinfo">Waiting for connection...</div>
    </div>
    <div class="ph">📢 Broadcasts <span class="badge" id="bcCnt">0</span></div>
    <div class="bc-section">
      <div class="bc-list" id="bcList"><div class="empty">No broadcasts yet</div></div>
    </div>
    <div class="sys-info">
      <div class="row"><span>📡 RSSI / SNR</span><b id="iSig">- / -</b></div>
      <div class="row"><span>📤 TX / 📥 RX</span><b id="iTr">0 / 0</b></div>
      <div class="row"><span>⚠️ Failed</span><b id="iFail">0</b></div>
      <div class="row"><span>💾 Storage</span><b id="iFs">-</b></div>
    </div>
  </div>
</div>

<div class="modal" id="bcm"><div class="modal-c">
<h3>📢 Send General Broadcast</h3>
<p style="font-size:12px;color:#bdc3c7;margin-bottom:10px">This message will be sent to ALL connected survivors.</p>
<textarea id="bcmsg" placeholder="Broadcast text (max 100 chars)" maxlength="100"></textarea>
<div class="modal-btns">
<button class="btn-c" onclick="closeBc()">Cancel</button>
<button class="btn-g" id="bcSendBtn" onclick="sendBc()">📤 Send</button>
</div>
</div></div>

<div class="toast" id="toast"></div>

<script>
const ML=41.02,MN=28.89;
let act=null,users={},broadcasts=[],filter='all',sysInfo={};
let upBase=0,upClientStart=0;
let sending=false;
let userScrolledUp=false;
let lastMsgCount=0;
const $=id=>document.getElementById(id);

// Detect if the user manually scrolled up
function setupScrollDetection(){
  const m=$('msgs');
  m.addEventListener('scroll',()=>{
    // If we are 50px away from the bottom, consider it "scrolled up"
    const atBottom=(m.scrollHeight-m.scrollTop-m.clientHeight)<50;
    userScrolledUp=!atBottom;
    if(atBottom)$('scrollBtn').classList.remove('show');
  });
}

function scrollBottom(){
  const m=$('msgs');
  m.scrollTop=m.scrollHeight;
  userScrolledUp=false;
  $('scrollBtn').classList.remove('show');
}

function pad(n){return String(n).padStart(2,'0')}
function fmtUp(s){const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60;return pad(h)+':'+pad(m)+':'+pad(sec)}
function fmtSize(b){if(b<1024)return b+'B';if(b<1024*1024)return (b/1024).toFixed(1)+'KB';return (b/1048576).toFixed(1)+'MB'}
function toast(msg){const t=$('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2500)}
function nowTime(){const d=new Date();return pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds())}
function nowDate(){const d=new Date();return pad(d.getDate())+'.'+pad(d.getMonth()+1)+'.'+d.getFullYear()}

function dist(a,b,c,d){const R=6371,dL=(c-a)*Math.PI/180,dN=(d-b)*Math.PI/180,x=Math.sin(dL/2)**2+Math.cos(a*Math.PI/180)*Math.cos(c*Math.PI/180)*Math.sin(dN/2)**2;return (R*2*Math.atan2(Math.sqrt(x),Math.sqrt(1-x))).toFixed(2)}
function distRssi(r){return Math.pow(10,(-50-r)/25).toFixed(1)}

function drawRadar(vL,vN,vR){
  const c=$('rdr'),x=c.getContext('2d');
  x.clearRect(0,0,200,200);
  for(let r of [35,70,98]){x.strokeStyle='rgba(127,140,141,.3)';x.beginPath();x.arc(100,100,r,0,2*Math.PI);x.stroke()}
  x.strokeStyle='rgba(127,140,141,.2)';
  x.beginPath();x.moveTo(100,2);x.lineTo(100,198);x.moveTo(2,100);x.lineTo(198,100);x.stroke();
  x.fillStyle='#3498db';x.beginPath();x.arc(100,100,6,0,2*Math.PI);x.fill();
  x.fillStyle='#fff';x.font='8px sans-serif';x.fillText('BASE',84,118);

  const info=$('rinfo');
  if(vL&&vN&&vL!='0'&&vN!='0'){
    let lD=(ML-vL)*1000,nD=(vN-MN)*1000,vX=100+nD,vY=100+lD;
    vX=Math.max(10,Math.min(190,vX));vY=Math.max(10,Math.min(190,vY));
    x.fillStyle='#e74c3c';x.beginPath();x.arc(vX,vY,7,0,2*Math.PI);x.fill();
    x.strokeStyle='#e74c3c';x.setLineDash([4,4]);x.lineWidth=2;
    x.beginPath();x.moveTo(100,100);x.lineTo(vX,vY);x.stroke();x.setLineDash([]);x.lineWidth=1;
    const m=dist(ML,MN,parseFloat(vL),parseFloat(vN));
    info.innerHTML=`<span style="color:#2ecc71">📍 GPS</span> • <b style="color:#e74c3c">${m} km</b><br><a href="https://maps.google.com/maps?q=${vL},${vN}" target="_blank" style="color:#3498db;font-size:10px">🗺️ Open in Maps</a>`;
  } else if(vR&&vR<0&&vR>-110){
    const d=distRssi(vR);let rd=Math.min(98,d/1.5);if(rd<12)rd=12;
    x.strokeStyle='#e67e22';x.setLineDash([4,4]);x.lineWidth=2;
    x.beginPath();x.arc(100,100,rd,0,2*Math.PI);x.stroke();x.setLineDash([]);x.lineWidth=1;
    info.innerHTML=`<span style="color:#e67e22">📡 RSSI</span> • ${vR}dBm<br><b style="color:#e67e22">~${d}m</b> (on radius)`;
  } else {
    info.innerHTML='<span style="color:#7f8c8d">No location data</span>';
  }
}

async function poll(){
  try{
    const r=await fetch('/api/state');
    if(r.status===401){location.href='/';return}
    const d=await r.json();
    users=d.users||{};
    broadcasts=d.broadcasts||[];
    sysInfo=d.sys||{};
    
    // Uptime sync: use backend value as baseline
    if(sysInfo.uptime!=null){
      upBase=sysInfo.uptime;
      upClientStart=Date.now();
    }
    if(act&&!users[act])clearChat();
    updateStats();
    render();
    renderBc();
    if(act&&users[act]){
      drawChat();
      drawRadar(users[act].lat,users[act].lon,users[act].rssi);
    }
  }catch(e){console.error('poll error:',e)}
}

// Client side uptime counter (ticks every second)
function tickUptime(){
  if(upClientStart===0)return;
  const elapsed=Math.floor((Date.now()-upClientStart)/1000);
  const total=upBase+elapsed;
  $('sUp').querySelector('.val').textContent=fmtUp(total);
}

function updateStats(){
  const u=Object.values(users);
  const crit=u.filter(x=>x.status==='Trapped'||x.status==='Injured').length;
  $('sUsers').querySelector('.val').textContent=u.length;
  $('sCrit').querySelector('.val').textContent=crit;
  $('sCrit').className='stat '+(crit>0?'err':'');
  const s=$('sLora');
  if(sysInfo.lora){s.className='stat ok';s.querySelector('.val').textContent='OK'}
  else{s.className='stat err';s.querySelector('.val').textContent='ERR'}
  $('iSig').textContent=(sysInfo.rssi||0)+'dBm / '+(sysInfo.snr||0)+'dB';
  $('iTr').textContent=(sysInfo.tx\vert{}\vert{}0)+' / '+(sysInfo.rx\vert{}\vert{}0);$('iFail').textContent=sysInfo.fail||0;
  if(sysInfo.fs_used!=null)$('iFs').textContent=fmtSize(sysInfo.fs_used)+'/'+fmtSize(sysInfo.fs_total);
}

function render(){
  const srch=$('srch').value.toLowerCase();
  const prio={Trapped:0,Injured:1,Safe:2};
  let arr=Object.entries(users);
  if(filter!=='all')arr=arr.filter(([k,v])=>v.status&&v.status.toLowerCase().includes(filter));
  if(srch)arr=arr.filter(([k,v])=>(v.name||'').toLowerCase().includes(srch));
  arr.sort(([,a],[,b])=>(prio[a.status]||3)-(prio[b.status]||3));

  $('userCnt').textContent=arr.length;
  if(arr.length===0){$('users').innerHTML='<div class="empty">No survivors listed yet</div>';return}

  $('users').innerHTML=arr.map(([id,u])=>{
    const cls=u.status==='Trapped'?'trapped':u.status==='Injured'?'injured':'safe';
    const pri=u.status==='Trapped'?'🚨':u.status==='Injured'?'🤕':'✅';
    const last=u.lastMsg||'';
    return `<div class="user ${cls} ${act===id?'act':''}" onclick="sel('${id}')">
      <div class="un">${u.name||'?'} <span style="font-size:11px;color:#95a5a6">${id.substring(4)}</span></div>
      <div class="ud"><span class="pri ${cls}">${pri} ${u.status||'?'}</span>${u.rssi||0}dBm • ${u.people||'?'} people</div>
      ${last?`<div class="um">"${last.substring(0,40)}${last.length>40?'...':''}"</div>`:''}
    </div>`;
  }).join('');
}

function renderBc(){
  $('bcCnt').textContent=broadcasts.length;
  if(broadcasts.length===0){$('bcList').innerHTML='<div class="empty">No broadcasts yet</div>';return}
  $('bcList').innerHTML=broadcasts.slice().reverse().map(b=>`
    <div class="bc-item">
      <button class="bc-del" onclick="delBc(${b.no})" title="Delete">🗑️</button>
      <div class="bc-text">${b.text}</div>
      <div class="bc-meta"><span>📅 ${b.date||'-'}</span><span>🕐 ${b.time}</span></div>
    </div>
  `).join('');
}

function setF(f){
  filter=f;
  document.querySelectorAll('.filters button').forEach(b=>b.classList.toggle('act',b.dataset.f===f));
  render();
}

function sel(id){
  act=id;
  lastMsgCount=0;
  userScrolledUp=false;
  $('scrollBtn').classList.remove('show');$('who').innerHTML=`<div>${users[id].name}</div><div class="det">${users[id].status} • ${users[id].people} people • ${users[id].rssi} dBm</div>`;
  $('mi').disabled=false;$('sbtn').disabled=false;
  $('kbtn').style.display='block';$('qrep').style.display='flex';
  render();drawChat();
  drawRadar(users[id].lat,users[id].lon,users[id].rssi);
}

function drawChat(){
  if(!act||!users[act])return;
  const m=users[act].msgs||[];
  const msgsBox=$('msgs');

  if(m.length===0){
    msgsBox.innerHTML='<div class="empty">No messages yet</div>';
    lastMsgCount=0;
    return;
  }

  // Check for new messages
  const newMsgCount=m.length;
  const hasNewMsg=newMsgCount>lastMsgCount;

  // Save scroll position before rendering
  const wasAtBottom=(msgsBox.scrollHeight-msgsBox.scrollTop-msgsBox.clientHeight)<50;
  const savedScrollTop=msgsBox.scrollTop;
  const savedScrollHeight=msgsBox.scrollHeight;

  // Render chat bubbles
  msgsBox.innerHTML=m.map(x=>{
    const ts=`${x.date||''} ${x.time||''}`.trim();
    if(x.type==='fail')return `<div class="msg fail">⚠️ Failed to deliver (#${x.no})</div>`;
    if(x.type==='out')return `<div class="msg out"><div class="h">BASE</div>${x.text}<span class="t">${ts}</span></div>`;
    return `<div class="msg in"><div class="h">${users[act].name}</div>${x.text}<span class="t">${ts}</span></div>`;
  }).join('');

  // Scrolling logic:
  // - First load -> snap to bottom
  // - User was already at bottom -> snap to bottom (auto-follow)
  // - User scrolled up + no new message -> KEEP position
  // - User scrolled up + NEW message -> KEEP position and show badge
  if(lastMsgCount===0||wasAtBottom){
    msgsBox.scrollTop=msgsBox.scrollHeight;
    $('scrollBtn').classList.remove('show');
  } else {
    // Offset the height difference to keep the view static
    const heightDiff=msgsBox.scrollHeight-savedScrollHeight;
    msgsBox.scrollTop=savedScrollTop+heightDiff;

    if(hasNewMsg){
      $('scrollBtn').classList.add('show');
    }
  }

  lastMsgCount=newMsgCount;
}

function clearChat(){
  act=null;
  lastMsgCount=0;
  userScrolledUp=false;
  $('scrollBtn').classList.remove('show');$('who').textContent='Select a survivor...';
  $('mi').disabled=true;$('sbtn').disabled=true;
  $('kbtn').style.display='none';$('qrep').style.display='none';$('msgs').innerHTML='<div class="empty">Select a survivor from the left panel</div>';
  drawRadar(0,0,0);
}

async function snd(){
  if(!act||sending)return;
  const m=$('mi').value.trim();if(!m)return;
  sending=true;
  $('sbtn').disabled=true;$('mi').disabled=true;
  document.querySelectorAll('.qrep button').forEach(b=>b.disabled=true);
  const t=nowTime();const d=nowDate();
  try{
    await fetch('/api/send?id='+act+'&msg='+encodeURIComponent(m)+'&t='+t+'&d='+d);
    $('mi').value='';
    userScrolledUp=false; // Force scroll to bottom after sending
    await poll();
    scrollBottom();
  }catch(e){console.error(e)}
  sending=false;
  $('sbtn').disabled=false;$('mi').disabled=false;
  document.querySelectorAll('.qrep button').forEach(b=>b.disabled=false);
  $('mi').focus();
}

async function qm(btn,t){
  if(sending)return;
  $('mi').value=t;
  await snd();
}

async function kick(){
  if(!act)return;
  if(!confirm('Kick '+users[act].name+' from the system?'))return;
  await fetch('/api/kick?id='+act);
  clearChat();toast('User removed');poll();
}

function openBc(){$('bcm').classList.add('show');$('bcmsg').focus()}
function closeBc(){$('bcm').classList.remove('show');$('bcmsg').value=''}
async function sendBc(){
  const m=$('bcmsg').value.trim();if(!m){alert('Message is empty');return}
  if(!confirm('Send to all connected survivors?'))return;
  $('bcSendBtn').disabled=true;
  const t=nowTime();const d=nowDate();
  try{
    await fetch('/api/bc?msg='+encodeURIComponent(m)+'&t='+t+'&d='+d);
    closeBc();toast('Broadcast sent');
    await poll();
  }catch(e){console.error(e)}
  $('bcSendBtn').disabled=false;
}

async function delBc(no){
  if(!confirm('Delete this broadcast?'))return;
  await fetch('/api/bc_del?no='+no);
  toast('Broadcast deleted');poll();
}

async function rst(){
  if(!confirm('Reset ENTIRE system? This cannot be undone.'))return;
  await fetch('/api/reset');
  clearChat();toast('System wiped');poll();
}

function exp(){window.open('/api/export','_blank')}

$('mi').onkeypress=e=>{if(e.key==='Enter'&&!e.target.disabled&&!sending)snd()};$('bcmsg').onkeypress=e=>{if(e.key==='Enter'&&e.ctrlKey)sendBc()};

setupScrollDetection();
poll();
setInterval(poll,800);
setInterval(tickUptime,1000);
</script></body></html>
)HTML";

bool isAuth() {
  if (server.hasHeader("Cookie")) {
    String c = server.header("Cookie");
    if (c.indexOf("AUTH=OK") != -1) return true;
  }
  return false;
}

void handleRoot() {
  if (isAuth()) server.send_P(200, "text/html", dashboard_html);
  else server.send_P(200, "text/html", login_html);
}

void handleLogin() {
  if (millis() < lockUntil) {
    server.sendHeader("Location", "/?e=lock");
    server.send(303);
    return;
  }
  
  if (server.hasArg("pwd") && server.arg("pwd") == PANEL_PASS) {
    failedAttempts = 0;
    server.sendHeader("Set-Cookie", "AUTH=OK; Path=/; Max-Age=86400");
    server.sendHeader("Location", "/");
    server.send(303);
  } else {
    failedAttempts++;
    if (failedAttempts >= LOGIN_MAX_ATTEMPT) {
      lockUntil = millis() + LOGIN_LOCK_TIME;
      failedAttempts = 0;
      Serial.println("[AUTH] LOCKED 5 min");
      server.sendHeader("Location", "/?e=lock");
    } else {
      server.sendHeader("Location", "/?e=1");
    }
    server.send(303);
  }
}

void handleLogout() {
  server.sendHeader("Set-Cookie", "AUTH=; Path=/; Max-Age=0");
  server.sendHeader("Location", "/");
  server.send(303);
  
  // Reset counters for the next login
  failedAttempts = 0;
  lockUntil = 0;
}

void handleApiState() {
  if (!isAuth()) { server.send(401, "application/json", "{}"); return; }

  String usersJson = "{";
  String bcJson = "[";
  String knownIds = "";
  bool firstUser = true;
  bool firstBc = true;

  File f = LittleFS.open(LOG_FILE, FILE_READ);
  if (f) {
    String allLines = "";
    while (f.available()) {
      String s = f.readStringUntil('\n');
      s.trim();
      if (s.length() > 0) allLines += s + "\n";
    }
    f.close();

    int pos = 0;
    // First pass: Gather all the broadcast messages
    while (pos < (int)allLines.length()) {
      int nl = allLines.indexOf('\n', pos);
      if (nl == -1) nl = allLines.length();
      String line = allLines.substring(pos, nl);
      pos = nl + 1;
      
      // Format: BC|no|date|time|text
      if (line.startsWith("BC|")) {
        String no = getValue(line, '|', 1);
        String date = getValue(line, '|', 2);
        String time = getValue(line, '|', 3);
        String text = getValue(line, '|', 4);
        
        if (!firstBc) bcJson += ",";
        firstBc = false;
        bcJson += "{\"no\":" + no + ",\"date\":\"" + jsonEscape(date) +
                  "\",\"time\":\"" + jsonEscape(time) +
                  "\",\"text\":\"" + jsonEscape(text) + "\"}";
      }
    }

    // Second pass: Gather user data and their individual messages
    pos = 0;
    while (pos < (int)allLines.length()) {
      int nl = allLines.indexOf('\n', pos);
      if (nl == -1) nl = allLines.length();
      String line = allLines.substring(pos, nl);
      pos = nl + 1;

      if (line.startsWith("FAIL|") || line.startsWith("BROADCAST|") ||
          line.startsWith("BC|") || line.startsWith("TX|") ||
          line.startsWith("MERKEZ|")) continue; // Skip these for user extraction

      String id = getValue(line, '|', 0);
      if (id.length() == 0) continue;
      if (knownIds.indexOf("[" + id + "]") != -1) continue;
      knownIds += "[" + id + "]";

      String name = "", status = "", people = "", lat = "0", lon = "0", rssi = "0", lastMsg = "";
      int p2 = 0;
      
      // Find the latest status for this specific ID
      while (p2 < (int)allLines.length()) {
        int nl2 = allLines.indexOf('\n', p2);
        if (nl2 == -1) nl2 = allLines.length();
        String l2 = allLines.substring(p2, nl2);
        p2 = nl2 + 1;
        if (l2.startsWith(id + "|")) {
          name = getValue(l2, '|', 1);
          status = getValue(l2, '|', 2);
          people = getValue(l2, '|', 3);
          lat = getValue(l2, '|', 4);
          lon = getValue(l2, '|', 5);
          rssi = getValue(l2, '|', 6);
          lastMsg = getValue(l2, '|', 8);
        }
      }

      String msgs = "[";
      bool firstMsg = true;
      int p3 = 0;
      
      // Third pass: Extract the chat history for this specific ID
      while (p3 < (int)allLines.length()) {
        int nl3 = allLines.indexOf('\n', p3);
        if (nl3 == -1) nl3 = allLines.length();
        String l3 = allLines.substring(p3, nl3);
        p3 = nl3 + 1;

        String mType = "", mTime = "", mDate = "", mText = "";
        if (l3.startsWith(id + "|")) {
          // Format: id|name|status|people|lat|lon|rssi|time|msg|date
          mType = "in";
          mTime = getValue(l3, '|', 7);
          mText = getValue(l3, '|', 8);
          mDate = getValue(l3, '|', 9);
        } else if (l3.startsWith("TX|" + id + "|")) {
          // Format: TX|id|time|msg|date
          mType = "out";
          mTime = getValue(l3, '|', 2);
          mText = getValue(l3, '|', 3);
          mDate = getValue(l3, '|', 4);
        } else continue;

        if (!firstMsg) msgs += ",";
        firstMsg = false;
        msgs += "{\"type\":\"" + mType + "\",\"time\":\"" + jsonEscape(mTime) +
                "\",\"date\":\"" + jsonEscape(mDate) +
                "\",\"text\":\"" + jsonEscape(mText) + "\"}";
      }
      msgs += "]";

      if (!firstUser) usersJson += ",";
      firstUser = false;
      usersJson += "\"" + id + "\":{";
      usersJson += "\"name\":\"" + jsonEscape(name) + "\",";
      usersJson += "\"status\":\"" + status + "\",";
      usersJson += "\"people\":\"" + people + "\",";
      usersJson += "\"lat\":\"" + lat + "\",";
      usersJson += "\"lon\":\"" + lon + "\",";
      usersJson += "\"rssi\":\"" + rssi + "\",";
      usersJson += "\"lastMsg\":\"" + jsonEscape(lastMsg) + "\",";
      usersJson += "\"msgs\":" + msgs;
      usersJson += "}";
    }
  }
  usersJson += "}";
  bcJson += "]";

  String sysJson = "{";
  sysJson += "\"lora\":" + String(isLoraActive ? "true" : "false") + ",";
  sysJson += "\"uptime\":" + String((millis() - bootTime) / 1000) + ",";
  sysJson += "\"tx\":" + String(totalTx) + ",";
  sysJson += "\"rx\":" + String(totalRx) + ",";
  sysJson += "\"fail\":" + String(totalFail) + ",";
  sysJson += "\"rssi\":" + String(lastRSSI) + ",";
  sysJson += "\"snr\":" + String(lastSNR, 1) + ",";
  sysJson += "\"fs_used\":" + String(LittleFS.usedBytes()) + ",";
  sysJson += "\"fs_total\":" + String(LittleFS.totalBytes());
  sysJson += "}";

  String resp = "{\"users\":" + usersJson + ",\"broadcasts\":" + bcJson + ",\"sys\":" + sysJson + "}";
  server.send(200, "application/json", resp);
}

void handleApiSend() {
  if (!isAuth()) { server.send(401, "text/plain", "NO"); return; }
  if (!server.hasArg("id") || !server.hasArg("msg")) {
    server.send(400, "text/plain", "BAD"); return;
  }
  
  String id = server.arg("id");
  String msg = sanitize(server.arg("msg"), MAX_MSG_LEN);
  String t = server.hasArg("t") ? server.arg("t") : "00:00:00";
  String d = server.hasArg("d") ? server.arg("d") : "";
  
  if (msg == "") { server.send(400, "text/plain", "EMPTY"); return; }

  Serial.println("[SEND] " + id + ": " + msg);

  File f = LittleFS.open(LOG_FILE, FILE_APPEND);
  if (f) { f.println("TX|" + id + "|" + t + "|" + msg + "|" + d); f.close(); }

  loraSend("MERKEZ|" + id + "|" + t + "|" + msg + "|" + d, true);
  logRotation();
  
  server.send(200, "text/plain", "OK");
}

void handleApiBc() {
  if (!isAuth()) { server.send(401, "text/plain", "NO"); return; }
  if (!server.hasArg("msg")) { server.send(400, "text/plain", "BAD"); return; }
  
  String msg = sanitize(server.arg("msg"), MAX_MSG_LEN);
  String t = server.hasArg("t") ? server.arg("t") : "00:00:00";
  String d = server.hasArg("d") ? server.arg("d") : "";
  
  if (msg == "") { server.send(400, "text/plain", "EMPTY"); return; }

  broadcastCounter++;
  Serial.println("[BC #" + String(broadcastCounter) + "] " + msg);

  // Save to our local log so the UI can fetch it
  File f = LittleFS.open(LOG_FILE, FILE_APPEND);
  if (f) {
    f.println("BC|" + String(broadcastCounter) + "|" + d + "|" + t + "|" + msg);
    f.close();
  }

  // Send to drone with the broadcast ID so we can delete it later if needed
  loraSend("BROADCAST|" + String(broadcastCounter) + "|" + t + "|" + msg + "|" + d, true);
  server.send(200, "text/plain", "OK");
}

void handleApiBcDel() {
  if (!isAuth()) { server.send(401, "text/plain", "NO"); return; }
  if (!server.hasArg("no")) { server.send(400, "text/plain", "BAD"); return; }
  
  String no = server.arg("no");

  // Remove it from the local log
  File tempFile = LittleFS.open("/tmp.txt", FILE_WRITE);
  File f = LittleFS.open(LOG_FILE, FILE_READ);
  if (f && tempFile) {
    while (f.available()) {
      String s = f.readStringUntil('\n');
      s.trim();
      if (s.length() == 0) continue;
      if (!s.startsWith("BC|" + no + "|")) tempFile.println(s);
    }
    f.close(); tempFile.close();
    LittleFS.remove(LOG_FILE);
    LittleFS.rename("/tmp.txt", LOG_FILE);
  }

  // Tell the drone to clear it as well
  loraSend("SYS_CMD|CLEAR_BC|" + no, false);
  Serial.println("[BC DEL] #" + no);
  server.send(200, "text/plain", "OK");
}

void handleApiKick() {
  if (!isAuth()) { server.send(401, "text/plain", "NO"); return; }
  if (!server.hasArg("id")) { server.send(400, "text/plain", "BAD"); return; }
  String targetId = server.arg("id");

  File tempFile = LittleFS.open("/tmp.txt", FILE_WRITE);
  File f = LittleFS.open(LOG_FILE, FILE_READ);
  if (f && tempFile) {
    while (f.available()) {
      String s = f.readStringUntil('\n');
      s.trim();
      if (s.length() == 0) continue;
      // Drop anything related to this user
      if (!s.startsWith(targetId + "|") && !s.startsWith("TX|" + targetId + "|"))
        tempFile.println(s);
    }
    f.close(); tempFile.close();
    LittleFS.remove(LOG_FILE);
    LittleFS.rename("/tmp.txt", LOG_FILE);
  }
  loraSend("SYS_CMD|CLEAR_USER|" + targetId, false);
  Serial.println("[KICK] " + targetId);
  server.send(200, "text/plain", "OK");
}

void handleApiReset() {
  if (!isAuth()) { server.send(401, "text/plain", "NO"); return; }
  LittleFS.remove(LOG_FILE);
  broadcastCounter = 0;
  loraSend("SYS_CMD|CLEAR", false);
  Serial.println("[RESET]");
  server.send(200, "text/plain", "OK");
}

void handleApiExport() {
  if (!isAuth()) { server.send(401, "text/plain", "NO"); return; }
  File f = LittleFS.open(LOG_FILE, FILE_READ);
  if (!f) { server.send(404, "text/plain", "NO_DATA"); return; }
  server.sendHeader("Content-Disposition", "attachment; filename=report.txt");
  server.streamFile(f, "text/plain");
  f.close();
}

void processLoraPacket(String decrypted) {
  if (decrypted.startsWith("ACK:")) {
    int c1 = 4, c2 = decrypted.indexOf(':', c1);
    if (c2 == -1) return;
    
    uint32_t no = decrypted.substring(c1, c2).toInt();
    for (int i = 0; i < MAX_PENDING; i++) {
      if (pendingPackets[i].active && pendingPackets[i].packetNo == no) {
        pendingPackets[i].active = false; // Got the ACK, we can stop retrying
        Serial.println("[ACK] #" + String(no));
        return;
      }
    }
  } else if (decrypted.startsWith("DATA:")) {
    int c1 = 5;
    int c2 = decrypted.indexOf(':', c1);
    int c3 = decrypted.indexOf(':', c2 + 1);
    if (c2 == -1 || c3 == -1) return;
    
    uint32_t no = decrypted.substring(c1, c2).toInt();
    String data = decrypted.substring(c3 + 1);

    if (isDuplicate(no)) { 
      loraSendAck(no); 
      return; 
    }
    
    loraSendAck(no);
    totalRx++;

    File f = LittleFS.open(LOG_FILE, FILE_APPEND);
    if (f) { f.println(data); f.close(); }
    logRotation();
    Serial.println("[SAVE] " + data.substring(0, 50));
  }
}

void blinkLED(int times, int duration) {
  for (int i = 0; i < times; i++) {
    digitalWrite(STATUS_LED, HIGH); delay(duration);
    digitalWrite(STATUS_LED, LOW); delay(duration);
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n========== BASE BOOT ==========");

  pinMode(STATUS_LED, OUTPUT);
  blinkLED(3, 100);

  bootTime = millis();
  randomSeed(esp_random());
  
  for (int i = 0; i < MAX_PENDING; i++) pendingPackets[i].active = false;
  for (int i = 0; i < 16; i++) lastReceivedPackets[i] = 0;

  if (!LittleFS.begin(true)) Serial.println("[FS] FAIL");
  else Serial.println("[FS] OK");

  WiFi.mode(WIFI_AP);
  esp_wifi_set_protocol(WIFI_IF_AP, WIFI_PROTOCOL_11B);
  WiFi.softAP(AP_NAME, WIFI_PASS, 11);
  WiFi.setTxPower(WIFI_POWER_19_5dBm);
  Serial.println("[WiFi] " + String(AP_NAME) + " @ " + WiFi.softAPIP().toString());

  const char* headers[] = {"Cookie"};
  server.collectHeaders(headers, 1);

  server.on("/", HTTP_GET, handleRoot);
  server.on("/login", HTTP_POST, handleLogin);
  server.on("/logout", HTTP_GET, handleLogout);
  server.on("/api/state", HTTP_GET, handleApiState);
  server.on("/api/send", HTTP_GET, handleApiSend);
  server.on("/api/bc", HTTP_GET, handleApiBc);
  server.on("/api/bc_del", HTTP_GET, handleApiBcDel);
  server.on("/api/kick", HTTP_GET, handleApiKick);
  server.on("/api/reset", HTTP_GET, handleApiReset);
  server.on("/api/export", HTTP_GET, handleApiExport);
  server.begin();
  Serial.println("[HTTP] Started");

  LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);
  if (!LoRa.begin(LORA_FREQ)) {
    isLoraActive = false;
    Serial.println("[LoRa] FAIL");
    blinkLED(10, 50);
  } else {
    isLoraActive = true;
    LoRa.setTxPower(20);
    
    #ifdef LORA_MODE_FAST
      LoRa.setSpreadingFactor(7);
      LoRa.setSignalBandwidth(250E3);
      LoRa.setCodingRate4(5);
      Serial.println("[LoRa] OK [FAST] SF7 BW250 CR4/5 20dBm");
    #else
      LoRa.setSpreadingFactor(10);
      LoRa.setSignalBandwidth(125E3);
      LoRa.setCodingRate4(8);
      Serial.println("[LoRa] OK [RANGE] SF10 BW125 CR4/8 20dBm");
    #endif
    
    LoRa.setPreambleLength(8);
    LoRa.setSyncWord(0xF3);
    LoRa.enableCrc();
  }

  digitalWrite(STATUS_LED, HIGH);
  Serial.println("========== READY ==========\n");
}

unsigned long lastLedToggle = 0;
bool ledState = true;

void loop() {
  server.handleClient();

  // Heartbeat LED
  if (millis() - lastLedToggle > 2000) {
    lastLedToggle = millis();
    ledState = !ledState;
    digitalWrite(STATUS_LED, ledState);
  }

  if (isLoraActive) {
    int packetSize = LoRa.parsePacket();
    if (packetSize) {
      String received = "";
      while (LoRa.available()) received += (char)LoRa.read();
      
      lastRSSI = LoRa.packetRssi();
      lastSNR = LoRa.packetSnr();
      String decrypted = decryptAES_CBC(received);
      
      if (decrypted != "") {
        Serial.println("[RX] RSSI=" + String(lastRSSI) + " SNR=" + String(lastSNR, 1));
        processLoraPacket(decrypted);
      }
    }
  }

  ackTimeoutCheck();
  yield();
  delay(1);
}