# This file is executed on every boot (including wake-boot from deepsleep)
import gc
import webrepl
webrepl.start()
gc.collect()
