# 硬件与外设（Hardware & Peripherals）

NullClaw 可以发现、烧录和操控通过 USB 连接的微控制器开发板。

## CLI 命令

```bash
nullclaw hardware scan             # 发现已连接的开发板
nullclaw hardware flash <path>     # 烧录固件
nullclaw hardware monitor          # 监控 USB 热插拔事件（Linux）
```

## 配置

```json
{
  "hardware": {
    "enabled": true,
    "transport": "serial",
    "serial_port": "/dev/ttyACM0",
    "baud_rate": 115200
  },
  "peripherals": {
    "enabled": true,
    "boards": [
      { "board": "nucleo-f401re", "transport": "serial", "path": "/dev/ttyACM0" }
    ]
  }
}
```

## 支持的开发板

| 开发板 | 类型 | Flash | GPIO |
|--------|------|-------|------|
| STM32 Nucleo-F401RE/F411RE | ARM Cortex-M4 | 512 KB | PA0-PC15 |
| Arduino Uno/Mega | AVR | 32-256 KB | D0-D53 |
| ESP32 (CH340) | Xtensa | 4 MB | GPIO0-GPIO39 |
| Raspberry Pi GPIO | ARM | — | GPIO 2-27 (sysfs) |

## 外设驱动

- **Serial**：通过 USB CDC 的 JSON 协议通信
- **Arduino**：使用 `arduino-cli` 编译和上传
- **STM32/Nucleo**：使用 `probe-rs` 烧录和调试
- **Raspberry Pi**：sysfs GPIO 接口

## Agent 工具

启用硬件后，agent 可使用 `hardware_info`、`hardware_memory`、`i2c`、`spi` 工具。

## 相关页面

- [架构总览](./architecture.md)
- [配置指南](./configuration.md)
