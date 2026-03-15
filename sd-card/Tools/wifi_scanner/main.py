import time

# --- LOCAL COLOR DEFINITIONS ---
COLOR_BLACK  = color565(0, 0, 0)
COLOR_GREEN  = color565(0, 255, 0)
COLOR_CYAN   = color565(0, 255, 255)
COLOR_RED    = color565(255, 0, 0)
COLOR_WHITE  = color565(255, 255, 255)
COLOR_YELLOW = color565(255, 255, 0)

# --- UI INITIALIZATION ---
display.clear(COLOR_BLACK)
display.fill_rectangle(0, 0, 240, 16, COLOR_CYAN)
display.draw_text8x8(5, 4, "WIFI SCANNER [ESP32]", COLOR_BLACK, COLOR_CYAN)
display.draw_hline(0, 16, 240, COLOR_WHITE)

display.draw_text8x8(10, 25, "Initializing module...", COLOR_YELLOW, COLOR_BLACK)

# --- FLUSH UART BUFFER ---
# Clear any old garbage data from the serial line
while esp_uart.any():
    esp_uart.read()

# --- SEND COMMAND TO BACKEND ---
display.draw_text8x8(10, 40, "Transmitting CMD...", COLOR_WHITE, COLOR_BLACK)
esp_uart.write(b'CMD:WIFI_SCAN\n')

# --- RECEIVE AND PARSE DATA ---
timeout_counter = 100 # 10 seconds timeout (100 * 0.1s)
is_scanning = True
y_pos = 65

display.draw_text8x8(10, 50, "Listening on UART3...", COLOR_CYAN, COLOR_BLACK)

while is_scanning and timeout_counter > 0:
    if esp_uart.any():
        raw_line = esp_uart.readline()
        if raw_line:
            try:
                line = raw_line.decode('utf-8').strip()
            except:
                continue # Ignore decoding errors from radio noise
            
            # Parse the specific [NET] tag from the C++ backend
            if line.startswith("[NET]"):
                # Example C++ output: [NET] SSID: MyWifi | RSSI: -60 | MAC: 00:11...
                parts = line.split("|")
                if len(parts) >= 2:
                    ssid_part = parts[0].replace("[NET] SSID:", "").strip()
                    rssi_part = parts[1].replace("RSSI:", "").strip()
                    
                    # Truncate SSID to fit the 240px portrait screen
                    display_text = f"{ssid_part[:16]} ({rssi_part}dBm)"
                    
                    if y_pos < 290: # Prevent writing off-screen
                        display.draw_text8x8(10, y_pos, display_text, COLOR_GREEN, COLOR_BLACK)
                        y_pos += 12
                        
            elif line.startswith("[END]"):
                is_scanning = False
                display.draw_text8x8(10, y_pos + 5, "Scan Completed.", COLOR_CYAN, COLOR_BLACK)
                
            elif line.startswith("[RES] Ag bulunamadi"): # From C++ backend
                is_scanning = False
                display.draw_text8x8(10, y_pos, "No networks found.", COLOR_RED, COLOR_BLACK)
    else:
        time.sleep(0.1)
        timeout_counter -= 1

if timeout_counter == 0:
    display.draw_text8x8(10, y_pos, "TIMEOUT! ESP32 Not Responding", COLOR_RED, COLOR_BLACK)

# --- EXIT ROUTINE ---
display.draw_hline(0, 305, 240, COLOR_WHITE)
display.draw_text8x8(10, 310, "Press [BACK] to exit", COLOR_YELLOW, COLOR_BLACK)

# Keep the app running until the user presses the 'GERI' (Back) button
while True:
    btn = buton_oku()
    if btn == 'GERI':
        break # Exiting the while loop ends the script and returns to the OS menu