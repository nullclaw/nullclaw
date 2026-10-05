# 硬件与外设（Hardware & Peripherals）

NullClaw 可以发现和操控通过 USB 连接的微控制器开发板。CLI 目前只实现了发现，
其余见下方[尚未实现](#尚未实现)。

## CLI 命令

```bash
nullclaw hardware scan             # 发现已连接的开发板
```

### 尚未实现

以下两个子命令可以被接受，但只是占位实现：它们只打印一条消息，并不会真正执行动作。

| 命令 | 当前行为 | 源码 |
|------|----------|------|
| `nullclaw hardware flash <path>` | 打印固件路径，然后输出 `Flash not yet implemented.` | `src/main.zig` `runHardware` |
| `nullclaw hardware monitor` | 输出 `Monitor not yet implemented.` 后退出。**不会**调用 `udevadm`，也不会监听热插拔事件。 | `src/main.zig` `runHardware` |

不要基于这两个命令编写脚本，它们都不执行 I/O。烧录请直接使用 `arduino-cli`
或 `probe-rs`（见[外设驱动](#外设驱动)）。

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

配置 `hardware.boards` 后，`allTools` 会注册：

| 工具 | 说明 |
|------|------|
| `hardware_board_info` | 列出已发现的开发板及其能力 |
| `hardware_memory` | 读取板载内存/寄存器 |
| `i2c` | I2C 总线读写操作 |

SPI 总线驱动存在于 `src/tools/spi.zig` 且可被导入，但**未**被 `allTools`
注册，因此 agent 无法使用。请将 `spi` 视为库能力，而非已发布的工具。

注意工具名是 `hardware_board_info`，而不是 `hardware_info` —— 实现文件名为
`src/tools/hardware_info.zig`，这是常见的混淆来源。

裸 `hardware` CLI 子命令与外设驱动是独立实现，不受上述 agent 工具注册的限制。

## 相关页面

- [架构总览](./architecture.md)
- [配置指南](./configuration.md)
