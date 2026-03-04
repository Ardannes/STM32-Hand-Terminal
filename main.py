from machine import Pin, SPI, UART
import time
from ili9341 import Display, color565

BLACK = color565(0, 0, 0)
GREEN = color565(0, 255, 0)
CYAN  = color565(0, 255, 255)
RED = color565(255, 0, 0)
WHITE = color565(255, 255, 255)

spi = SPI(1, baudrate=30000000, polarity=0, phase=0)
cs = Pin('PA2', Pin.OUT)
dc = Pin('PA3', Pin.OUT)
rst = Pin('PA4', Pin.OUT)

display = Display(spi, cs, dc, rst, width=240, height=320, rotation=90)

def write_terminal(headline, messages, msg_color=GREEN):
    display.clear(BLACK)
    
    display.fill_rectangle(0, 0, 320, 16, CYAN)
    display.draw_text8x8(5, 4, headline, BLACK, CYAN)
    
    display.draw_hline(0, 16, 320, WHITE)
    
    y_coord = 25
    for satir in messages:
        display.draw_text8x8(5, y_coord, satir, msg_color, BLACK)
        y_coord += 12
        if y_coord > 220:
            break

write_terminal('CYBERDECK INIT v1.0', ['SYSTEM Starting...', 'Loading...'])
time.sleep(1)

esp_uart = UART(3, baudrate=115200)

write_terminal('NET CONNECTION', ['UART3 (PD8/PD9)', 'ESP32 Module Calling...'], WHITE)

esp_uart.write(b'AT\r\n')
time.sleep(0.5)

if esp_uart.any():
    cevap = esp_uart.read().decode('utf-8').strip()
    if "OK" in cevap:
        write_terminal('WI-FI SCANNER', ['Module Ready (OK).', 'Scanning Networks...'])
        
        while esp_uart.any():
            esp_uart.read()
            
        esp_uart.write(b'WIFI_SCAN\r\n')
        
        timeout = 60
        while not esp_uart.any() and timeout > 0:
            time.sleep(0.1)
            timeout -= 1
            
        if esp_uart.any():
            data = esp_uart.read().decode('utf-8')
            network_list = data.strip().split('\r\n')
            
            if "SCAN_COMPLATE" in network_list:
                network_list.remove("SCAN_COMPLATE")
                
            write_terminal('FOUND WI-FI NETWORKS', network_list, GREEN)
        else:
            write_terminal('SYSTEM ERROR', ['Scan Timeout!', 'ESP32 no response.'], RED)
    else:
        write_terminal('SYSTEM ERROR', ['Unknown Answer:', cevap], RED)
else:
    write_terminal('HARDWARE ERROR', ['ESP32 Not Found!', 'Check Wires.'], RED)