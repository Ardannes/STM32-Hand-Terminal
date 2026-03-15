#include "globals.h"
#include "sniffer_tools.h"
#include "wifi_tools.h"
// İleride buraya: #include "kamera_tools.h" eklenecek

SystemState currentState = STATE_IDLE;

void setup() {
  // STM32 ile haberleşme hızı (PD8 ve PD9 pinlerine bağlı olan hat)
  Serial.begin(115200);

  // Başlangıç mesajı (STM32'nin ekranına düşecek)
  Serial.println("[SYS] ESP32 Backend Baslatildi. Durum: IDLE");
}

void loop() {
  // 1. STM32'den Gelen Komutları Dinle
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();

    // ── Durum değiştirme komutları ──
    if (cmd == "CMD:WIFI_SCAN") {
      currentState = STATE_WIFI_SCAN;
    } else if (cmd == "CMD:SNIFFER_START") {
      snifferStart();
      currentState = STATE_SNIFFER;
    } else if (cmd == "CMD:SNIFFER_STOP") {
      snifferStop();
      currentState = STATE_IDLE;
    } else if (cmd == "CMD:IDLE") {
      if (currentState == STATE_SNIFFER)
        snifferStop();
      currentState = STATE_IDLE;
      Serial.println("[SYS] Sisteme bosta (IDLE) moduna gecildi.");
    }
    // ── Sniffer alt-komutları (state değiştirmez) ──
    else if (cmd.startsWith("CMD:SNIFFER_")) {
      snifferHandleCommand(cmd);
    }
    // İleride: CMD:CAMERA_ON vb.
  }

  // 2. Durum Makinesini İşlet
  switch (currentState) {
  case STATE_IDLE:
    break;

  case STATE_WIFI_SCAN:
    executeWifiScan();
    currentState = STATE_IDLE;
    break;

  case STATE_SNIFFER:
    // Promiscuous mode aktif — sürekli paket işle
    snifferLoop();
    break;

  default:
    break;
  }
}