#include "wifi_tools.h"
#include <WiFi.h>

void executeWifiScan() {
  Serial.println("[INFO] Wi-Fi taramasi baslatildi...");
  
  // Wi-Fi modülünü istasyon moduna al ve önceki bağlantıları kes
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  int n = WiFi.scanNetworks();
  
  if (n == 0) {
    Serial.println("[RES] Ag bulunamadi.");
  } else {
    Serial.print("[RES] Bulunan ag sayisi: ");
    Serial.println(n);
    
    for (int i = 0; i < n; ++i) {
      // STM32'nin Python kodunda kolayca parçalayabilmesi (parse) için standart format
      Serial.print("[NET] SSID: ");
      Serial.print(WiFi.SSID(i));
      Serial.print(" | RSSI: ");
      Serial.print(WiFi.RSSI(i));
      Serial.print(" | MAC: ");
      Serial.println(WiFi.BSSIDstr(i));
      delay(10); // UART tamponunu boğmamak için ufak bekleme
    }
  }
  
  Serial.println("[END] Tarama tamamlandi.");
  
  // RAM'i temizlemek için scan sonuçlarını sil
  WiFi.scanDelete(); 
}