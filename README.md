# Netstack

Netstack is a network stack written in Go.

This is currently only a hardly modified fork of [github.com/google/netstack](github.com/google/netstack). The goal of this project is to fit it onto the [ixy.go](https://github.com/ixy-languages/ixy.go) driver and evaluate the performance of the then pure userspace NIC driver + netstack. If you want to use the google netsteack, head over to the original repository.

### Disclaimer

This project is in no way shape or form affiliated with Google.

As with ixy.go, this project is not production ready. Do not use in critical environments. DMA access may corrupt memory.
