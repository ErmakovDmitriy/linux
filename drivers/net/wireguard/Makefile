ccflags-y := -D'pr_fmt(fmt)=KBUILD_MODNAME ": " fmt'
ccflags-$(CONFIG_WIREGUARD_DEBUG) += -DDEBUG
wireguard-y := main.o
wireguard-y += noise.o
wireguard-y += device.o
wireguard-y += peer.o
wireguard-y += timers.o
wireguard-y += queueing.o
wireguard-y += send.o
wireguard-y += receive.o
wireguard-y += socket.o
wireguard-y += peerlookup.o
wireguard-y += allowedips.o
wireguard-y += ratelimiter.o
wireguard-y += cookie.o
wireguard-y += netlink.o
obj-$(CONFIG_WIREGUARD) := wireguard.o


wireguard-test-y += peerlookup.o
wireguard-test-y += peer.o
wireguard-test-y += cookie.o
wireguard-test-y += queueing.o
wireguard-test-y += timers.o
wireguard-test-y += send.o
wireguard-test-y += receive.o
wireguard-test-y += allowedips.o
wireguard-test-y += device.o
wireguard-test-y += noise.o
wireguard-test-y += netlink.o
wireguard-test-y += socket.o
wireguard-test-y += ratelimiter.o

wireguard-test-y += test-hashtable.o
obj-m := wireguard-test.o
