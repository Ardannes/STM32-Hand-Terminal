#include "globals.h"
#include "wifi_tools.h"
// İleride buraya: #include "sniffer_tools.h", #include "kamera_tools.h" eklenecek

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
    cmd.trim(); // Boşlukları ve satır sonu karakterlerini temizle
    
    // Gelen komuta göre ESP32'nin durumunu (State) değiştir
    if (cmd == "CMD:WIFI_SCAN") {
      currentState = STATE_WIFI_SCAN;
    } 
    else if (cmd == "CMD:IDLE") {
      currentState = STATE_IDLE;
      Serial.println("[SYS] Sisteme bosta (IDLE) moduna gecildi.");
    }
    // İleride diğer komutlar eklenecek: CMD:SNIFFER_START, CMD:CAMERA_ON vb.
  }

  // 2. Durum Makinesini İşlet (Görev Dağıtımı)
  switch (currentState) {
    case STATE_IDLE:
      // Boşta bekle, hiçbir işlem yapma.
      break;
      
    case STATE_WIFI_SCAN:
      // wifi_tools.cpp içindeki fonksiyonu çağır
      executeWifiScan();
      // Tarama bitince otomatik olarak boşa dön (One-Shot Task)
      currentState = STATE_IDLE; 
      break;
      
    case STATE_SNIFFER:
      // Sniffer kodları buraya gelecek
      break;
  }
}