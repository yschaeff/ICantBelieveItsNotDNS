# This file is executed on every boot (including wake-boot from deepsleep)
import gc

## This creates a wifi connection with
## any of our know access points
import net_utils
from trusted_networks import NETWORKS
net_utils.connect_to_ap(NETWORKS)

import webrepl
webrepl.start()

gc.collect()
