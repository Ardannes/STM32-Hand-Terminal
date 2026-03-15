#ifndef GLOBALS_H
#define GLOBALS_H

#include <Arduino.h>

// İşletim Sisteminin Durumları (State Machine)
enum SystemState {
  STATE_IDLE,         // Boşta, komut bekliyor (Güç tasarrufu)
  STATE_WIFI_SCAN,    // Wi-Fi taraması yapıyor
  STATE_SNIFFER,      // Paket yakalama (Promiscuous) modunda
  STATE_CAMERA,       // Kamera açık, yayın yapıyor
  STATE_DEAUTHER      // Deauth saldırısı yapıyor
};

// Global durum değişkeni (extern ile diğer dosyalara açıyoruz)
extern SystemState currentState;

#endif