from machine import Pin, SPI
import ssd1306

spi = SPI(1, baudrate=10000000, polarity=0, phase=0)

cs = Pin('PA2', Pin.OUT)
dc = Pin('PA3', Pin.OUT)
res = Pin('PA4', Pin.OUT)

width = 128
height = 64

display = ssd1306.SSD1306_SPI(width, height, spi, dc, res, cs)

display.contrast(200)

display.fill(0)
display.text('Terminal Init...', 0, 0, 1)
display.text('System Ready!', 0, 16, 1)
display.show()
