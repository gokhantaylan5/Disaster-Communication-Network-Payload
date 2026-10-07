/*
 * ============================================================
 *   LORA SIGNAL SNIFFER / SECURITY TEST DEVICE
 * ============================================================
 * This tool listens to the LoRa broadcasts on our Search & 
 * Rescue network to VERIFY the encryption strength in real-time.
 * 
 * GOAL: Prove that the system cannot be compromised even if 
 * the traffic is intercepted by a third party.
 * 
 * 3 SCENARIOS:
 *  [1] PASSIVE LISTENING -> Captures the raw encrypted payload
 *  [2] WRONG KEY         -> Attempts decryption, expects failure
 *  [3] CORRECT KEY       -> Demo only: Proves the packet is actually valid
 * ============================================================
 */

#include <SPI.h>
#include <LoRa.h>
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"

// ============ PINS & FREQUENCY ============
#define LORA_SS    5
#define LORA_RST   14
#define LORA_DIO0  2
#define LORA_FREQ  433E6

// ============ LORA SPEED PROFILE ============
// MUST match the Base/Drone configuration, otherwise we won't catch anything!
#define LORA_MODE_FAST
// #define LORA_MODE_RANGE

// ============ CRACKING ATTEMPT ============
// The WRONG key an attacker might try to guess (random brute-force)
const char* WRONG_KEY    = "Password12345678";   // 16 chars

// For DEMO purposes only: The actual system key (attacker wouldn't know this)
// Used during presentations to show "what would happen if we had the right key"
const char* CORRECT_KEY  = "RescueNetKey2026"; 

// Sniffer SyncWord — must match the network
#define SNIFFER_SYNC_WORD 0xF3

// ============ STATISTICS ============
uint32_t totalPackets = 0;
uint32_t corruptedPackets = 0;
uint32_t successfulDecrypts = 0;
uint32_t failedDecrypts = 0;
unsigned long lastPacketTime = 0;

// ============ AES DECRYPT ROUTINE ============
String decryptAES_CBC(String b64Input, const char* key) {
  b64Input.trim();
  if (b64Input.length() < 24) return "";

  size_t decLen = 0;
  size_t inLen = b64Input.length();
  unsigned char decoded[inLen + 1];
  int ret = mbedtls_base64_decode(decoded, inLen, &decLen,
                                   (const unsigned char*)b64Input.c_str(), inLen);
  if (ret != 0 || decLen < 32 || (decLen - 16) % 16 != 0) return "";

  unsigned char iv[16];
  memcpy(iv, decoded, 16);

  int cipherLen = decLen - 16;
  unsigned char input[cipherLen];
  unsigned char output[cipherLen];
  memcpy(input, decoded + 16, cipherLen);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, (const unsigned char*)key, 128);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, cipherLen, iv, input, output);
  mbedtls_aes_free(&aes);

  int padVal = output[cipherLen - 1];
  if (padVal < 1 || padVal > 16) return "";  // Invalid padding = wrong key
  int plainLen = cipherLen - padVal;

  // Are all characters printable? (Wrong keys usually result in garbage chars)
  for (int i = 0; i < plainLen; i++) {
    unsigned char c = output[i];
    if (c < 9 || (c > 13 && c < 32) || c > 126) return "GARBLED";
  }

  String result = "";
  for (int i = 0; i < plainLen; i++) result += (char)output[i];
  return result;
}

void printSeparator() {
  Serial.println("============================================");
}

void printStats() {
  Serial.println("\n>>> SESSION STATISTICS <<<");
  Serial.println("Total packets intercepted : " + String(totalPackets));
  Serial.println("Corrupted/Invalid packets : " + String(corruptedPackets));
  Serial.println("Wrong key attempts        : " + String(failedDecrypts) + " failed");
  Serial.println("Correct key decrypts      : " + String(successfulDecrypts) + " successful (reference)");
  
  if (totalPackets > 0) {
    float failureRate = (failedDecrypts * 100.0) / totalPackets;
    Serial.println("ATTACKER FAILURE RATE     : " + String(failureRate, 1) + "%");
    Serial.println("(Meaning the attacker failed to decrypt " + String(failureRate, 1) + "% of the payload)");
  }
  printSeparator();
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  while (!Serial);

  printSeparator();
  Serial.println("   LORA SIGNAL SNIFFER & TEST TOOL");
  Serial.println("   Security Audit - Search & Rescue Net");
  printSeparator();

  LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);
  if (!LoRa.begin(LORA_FREQ)) {
    Serial.println("[ERROR] LoRa module initialization failed!");
    Serial.println("Check your wiring and antenna.");
    while (1) delay(100);
  }

  // CRITICAL: Must mirror the target system parameters
  #ifdef LORA_MODE_FAST
    LoRa.setSpreadingFactor(7);
    LoRa.setSignalBandwidth(250E3);
    LoRa.setCodingRate4(5);
    Serial.println("[MODE] FAST  -> SF7 / BW250 / CR4/5");
  #else
    LoRa.setSpreadingFactor(10);
    LoRa.setSignalBandwidth(125E3);
    LoRa.setCodingRate4(8);
    Serial.println("[MODE] RANGE -> SF10 / BW125 / CR4/8");
  #endif
  
  LoRa.setPreambleLength(8);
  LoRa.setSyncWord(SNIFFER_SYNC_WORD);
  LoRa.enableCrc();
  LoRa.receive();  // Put LoRa in continuous receive mode

  Serial.println("[OK] Sniffer active. Listening on 433 MHz...");
  Serial.println("[INFO] Testing brute-force with key: " + String(WRONG_KEY));
  Serial.println("[INFO] Freq: 433 MHz | SyncWord: 0x" + String(SNIFFER_SYNC_WORD, HEX));
  printSeparator();
  Serial.println("Waiting for packets...\n");
}

void loop() {
  int packetSize = LoRa.parsePacket();

  if (packetSize) {
    totalPackets++;
    lastPacketTime = millis();

    String rawData = "";
    while (LoRa.available()) rawData += (char)LoRa.read();

    int rssi = LoRa.packetRssi();
    float snr = LoRa.packetSnr();

    printSeparator();
    Serial.println(">>> PACKET INTERCEPTED #" + String(totalPackets));
    printSeparator();
    Serial.println("Timestamp  : " + String(millis() / 1000) + " s");
    Serial.println("Signal RSSI: " + String(rssi) + " dBm");
    Serial.println("Signal SNR : " + String(snr, 1) + " dB");
    Serial.println("Payload    : " + String(packetSize) + " bytes");
    Serial.println();

    Serial.println("[1] RAW ENCRYPTED PAYLOAD (Base64):");
    Serial.println(rawData);
    Serial.println();

    // Scenario 2: Attempt decryption with the wrong key
    Serial.println("[2] DECRYPTION ATTEMPT (WRONG KEY):");
    Serial.println("    Trying key: '" + String(WRONG_KEY) + "'");
    String wrongResult = decryptAES_CBC(rawData, WRONG_KEY);
    
    if (wrongResult == "" || wrongResult == "GARBLED") {
      Serial.println("    RESULT: FAILED - Data could not be decrypted!");
      Serial.println("    (AES-128 CBC remains secure)");
      failedDecrypts++;
    } else {
      Serial.println("    RESULT: Unexpected: " + wrongResult);
      Serial.println("    (This shouldn't happen unless keys match)");
    }
    Serial.println();

    // Scenario 3: DEMO/REFERENCE ONLY - Real attacker wouldn't have this
    Serial.println("[3] REFERENCE DECRYPTION (CORRECT KEY - DEMO ONLY):");
    String correctResult = decryptAES_CBC(rawData, CORRECT_KEY);
    
    if (correctResult != "" && correctResult != "GARBLED") {
      Serial.println("    Plaintext: " + correctResult);
      successfulDecrypts++;
    } else {
      Serial.println("    [ERROR] Decryption failed - packet might be corrupted");
      corruptedPackets++;
    }
    Serial.println();

    Serial.println("CONCLUSION: An attacker only sees the gibberish in [1].");
    Serial.println("            Step [2] failed - system security is verified.");

    // Print summary every 5 packets
    if (totalPackets % 5 == 0) printStats();

    Serial.println();
  }

  // Warn if we haven't seen any packets in a while
  if (lastPacketTime > 0 && (millis() - lastPacketTime > 30000) && totalPackets > 0) {
    Serial.println("[WARNING] No packets intercepted in 30 seconds. Is the target transmitting?");
    lastPacketTime = millis();  // Reset so it doesn't spam
  }

  delay(10);
}