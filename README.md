# Secureboot-Spoofer
Runtime SecureBoot spoofer: patches all four query surfaces (registry, NtQuerySystemInformation class 145, SharedUserData, EFI variables) from a manually-mapped kernel driver with no registered callbacks, no SSDT hooks, and no visible driver object.
