# Fixtures

Binary request/response captures replayed by `selftest`. Most are real C#-parity
captures; the synthetic ones are noted inline.

`Arp.selftest` 为**合成** fixture（无 C# 对应物，spec §3.6）：一个 42 字节的 GARP
帧，sender 192.168.1.50 / MAC 00:11:22:33:44:55 自宣告。
