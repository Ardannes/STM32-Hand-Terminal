import os
import time
import gc # Garbage Collector (RAM Temizleyici)
from machine import Pin, SPI, SoftSPI, UART
from ili9341 import Display, color565
import sdcard

# --- RENK PALETİ ---
SIYAH = color565(0, 0, 0)
YESIL = color565(0, 255, 0)
CYAN  = color565(0, 255, 255)
KIRMIZI = color565(255, 0, 0)
BEYAZ = color565(255, 255, 255)
SARI = color565(255, 255, 0)

# --- DONANIM KURULUMLARI ---

# 1. Ekran (SPI 1)
spi1 = SPI(1, baudrate=30000000, polarity=0, phase=0)
display = Display(spi1, Pin('PE7', Pin.OUT), Pin('PE8', Pin.OUT), Pin('PE9', Pin.OUT), width=240, height=320, rotation=0)

# 2. ESP32 UART İletişimi (UART 3) - Durum makinesi komutları için hazır
esp_uart = UART(3, baudrate=115200)

# 3. Buton Matrisi
satirlar = [Pin('PD0', Pin.IN, Pin.PULL_DOWN), Pin('PD1', Pin.IN, Pin.PULL_DOWN), Pin('PD2', Pin.IN, Pin.PULL_DOWN)]
sutunlar = [Pin('PD3', Pin.OUT), Pin('PD4', Pin.OUT)]
buton_haritasi = [['YUKARI', 'ASAGI'], ['SOL', 'SAG'], ['ONAY', 'GERI']]

def buton_oku():
    basilan = None
    for s_idx, sutun in enumerate(sutunlar):
        sutun.value(1) 
        for r_idx, satir in enumerate(satirlar):
            if satir.value() == 1: 
                basilan = buton_haritasi[r_idx][s_idx]
                break
        sutun.value(0) 
        if basilan: break
    if basilan: time.sleep(0.2) # Debounce
    return basilan

# --- ÇEKİRDEK (KERNEL) FONKSİYONLARI ---
def ust_cubugu_ciz():
    display.clear(SIYAH)
    display.fill_rectangle(0, 0, 240, 16, CYAN)
    display.draw_text8x8(5, 4, "MFTerminal v0.1", SIYAH, CYAN)
    display.draw_hline(0, 16, 240, BEYAZ)

def log_yaz(mesaj, renk=BEYAZ, satir=30):
    display.draw_text8x8(10, satir, mesaj, renk, SIYAH)

# --- BOOT SEQUENCE (SİSTEM BAŞLATMA) ---
ust_cubugu_ciz()
log_yaz("SISTEM BASLATILIYOR...", BEYAZ, 30)
log_yaz("Hafiza Birimi Araniyor...", SARI, 50)
time.sleep(0.5)

# SD Kart Kurulumu (SoftSPI - TFT Arkası)
cs_sd = Pin('PB12', Pin.OUT, value=1)
miso_pini = Pin('PB14', Pin.IN, Pin.PULL_UP)
spi_sd = SoftSPI(baudrate=2000000, polarity=0, phase=0, sck=Pin('PB13'), mosi=Pin('PB15'), miso=miso_pini)

sd_aktif = False

aktif_dizin = '/sd' # Başlangıç klasörümüz
araclar = [] 
arac_yollari = [] 

def is_dir(yol):
    """Bir yolun klasör olup olmadığını kontrol eder."""
    try:
        # os.stat()[0] dosya modunu döndürür. 0x4000 (16384) bit'i klasör demektir.
        return (os.stat(yol)[0] & 0x4000) != 0
    except:
        return False


try:
    sd = sdcard.SDCard(spi_sd, cs_sd)
    vfs = os.VfsFat(sd)
    os.mount(vfs, '/sd')
    log_yaz("[OK] SD KART BAGLANDI", YESIL, 70)
    sd_aktif = True
    
    # 'tools' klasörü yoksa oluştur
    try:
        os.listdir('/sd/tools')
    except:
        os.mkdir('/sd/tools')
        
except Exception as e:
    log_yaz("[HATA] SD Kart Bulunamadi!", KIRMIZI, 70)
    log_yaz(str(e), KIRMIZI, 90)

time.sleep(1)

# --- DİNAMİK MENÜ OLUŞTURUCU ---
def menuyu_guncelle():
    global araclar, arac_yollari, aktif_dizin
    araclar.clear()
    arac_yollari.clear()
    
    if sd_aktif:
        # Eğer kök dizinde değilsek, en başa "Üst Klasör" seçeneği ekle
        if aktif_dizin != '/sd':
            araclar.append("[..] Ust Klasore Cik")
            # /sd/tools/test -> /sd/tools şeklinde üst dizini bul
            ust_dizin = aktif_dizin.rsplit('/', 1)[0]
            if ust_dizin == '': ust_dizin = '/sd'
            arac_yollari.append(ust_dizin)

        try:
            # Dosyaları al ve alfabetik sırala
            dosyalar = sorted(os.listdir(aktif_dizin))
            
            for dosya in dosyalar:
                tam_yol = aktif_dizin + '/' + dosya
                
                if is_dir(tam_yol):
                    araclar.append(f"[{dosya}]") # Klasörleri köşeli parantezle göster
                elif dosya.endswith('.py'):
                    # Çalıştırılabilir Python scriptleri
                    gosterim_adi = dosya
                    araclar.append(gosterim_adi)
                else:
                    # Diğer tüm dosyalar (txt, log, ini vb.)
                    araclar.append(dosya) 
                    
                arac_yollari.append(tam_yol)
                
        except Exception as e:
            araclar.append("Dizin Okuma Hatasi!")
            arac_yollari.append("hata")
            
    if len(araclar) == 0:
        araclar.append("(Klasor Bos)")
        arac_yollari.append("hata")
secili_index = 0

def menuyu_ciz():
    display.fill_rectangle(0, 17, 240, 303, SIYAH)
    y_koor = 30
    for i, oge in enumerate(araclar):
        if i == secili_index:
            display.draw_text8x8(10, y_koor, "> " + oge, CYAN, SIYAH)
        else:
            display.draw_text8x8(10, y_koor, "  " + oge, YESIL, SIYAH)
        y_koor += 15

# İlk menüyü çiz
menuyu_guncelle()
menuyu_ciz()
# --- İŞLETİM SİSTEMİ ANA DÖNGÜSÜ ---
while True:
    islem = buton_oku()
    
    if islem:
        if islem == 'ASAGI':
            secili_index = (secili_index + 1) % len(araclar)
            menuyu_ciz()
            
        elif islem == 'YUKARI':
            secili_index = (secili_index - 1) % len(araclar)
            menuyu_ciz()
            
        elif islem == 'ONAY':
            hedef_yol = arac_yollari[secili_index]
            secilen_isim = araclar[secili_index]
            
            if hedef_yol == "hata":
                pass # Hata mesajına veya boş klasöre tıklandıysa hiçbir şey yapma
                
            elif is_dir(hedef_yol):
                # KLASÖRE GİRİŞ: Tıklanan şey bir klasörse içine gir
                aktif_dizin = hedef_yol
                secili_index = 0 # İmleci en başa al
                menuyu_guncelle()
                menuyu_ciz()
                
            elif hedef_yol.endswith('.py'):
                # PYTHON KODU ÇALIŞTIRMA
                display.fill_rectangle(0, 17, 240, 303, SIYAH)
                log_yaz("MODUL YUKLENIYOR...", BEYAZ, 30)
                log_yaz(secilen_isim, CYAN, 50)
                time.sleep(0.5)
                
                try:
                    gc.collect() # RAM'i temizle
                    with open(hedef_yol, 'r') as f:
                        tool_kodu = f.read()
                    exec(tool_kodu, globals()) # Kodu işletim sistemi yetkileriyle çalıştır
                except Exception as e:
                    display.fill_rectangle(0, 17, 240, 303, SIYAH)
                    log_yaz("CRASH REPORT:", KIRMIZI, 30)
                    log_yaz(str(e), KIRMIZI, 50)
                    log_yaz("Cikmak icin GERI tusuna basin", BEYAZ, 90)
                    while buton_oku() != 'GERI':
                        time.sleep(0.1)
                        
                # Tool kapandığında donanımı sıfırla ve menüye dön
                gc.collect() 
                ust_cubugu_ciz()
                menuyu_guncelle() 
                menuyu_ciz()
                
            else:
                # DESTEKLENMEYEN DOSYA (Örn: .txt veya .log dosyası seçilirse)
                display.fill_rectangle(0, 17, 240, 303, SIYAH)
                log_yaz("BILGI:", SARI, 30)
                log_yaz("Bu dosya calistirilamaz.", BEYAZ, 50)
                log_yaz(secilen_isim, CYAN, 70)
                time.sleep(1.5)
                menuyu_ciz()

        elif islem == 'GERI':
            # ÜST KLASÖRE ÇIKMA: Eğer kök dizinde (/sd) değilsek bir üst klasöre dön
            if aktif_dizin != '/sd':
                ust_dizin = aktif_dizin.rsplit('/', 1)[0]
                if ust_dizin == '': ust_dizin = '/sd'
                aktif_dizin = ust_dizin
                secili_index = 0
                menuyu_guncelle()
                menuyu_ciz()