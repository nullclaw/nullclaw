# Hardware & Peripherals

NullClaw can discover, flash, and interact with microcontroller boards over USB.

## CLI Commands

```bash
nullclaw hardware scan             # Discover connected boards
nullclaw hardware flash <path>     # Flash firmware to a board
nullclaw hardware monitor          # Monitor USB hotplug events (Linux)
```

## Configuration

```json
{
  "hardware": {
    "enabled": true,
    "transport": "serial",
    "serial_port": "/dev/ttyACM0",
    "baud_rate": 115200,
    "workspace_datasheets": false
  },
  "peripherals": {
    "enabled": true,
    "boards": [
      {
        "board": "nucleo-f401re",
        "transport": "serial",
        "path": "/dev/ttyACM0",
        "baud": 115200
      }
    ]
  }
}
```

## Supported Boards

| Board | VID:PID | Flash | GPIO |
|-------|---------|-------|------|
| STM32 Nucleo-F401RE | 0483:374b | 512 KB | PA0-PC15, ADC |
| STM32 Nucleo-F411RE | 0483:3748 | 512 KB | PA0-PC15, ADC |
| Arduino Uno | 2341:0043 | 32 KB | D0-D13, A0-A5 |
| Arduino Mega | 2341:0042 | 256 KB | D0-D53, A0-A15 |
| ESP32 (CH340) | 1a86:7523 | 4 MB | GPIO0-GPIO39, ADC |
| Raspberry Pi GPIO | — | — | GPIO 2-27 (sysfs) |

## Peripheral Drivers

### Serial (Arduino, ESP32)

Communicates via newline-delimited JSON over USB CDC:

```json
{"id": "1", "cmd": "gpio_read", "args": {"pin": 13}}
→ {"id": "1", "ok": true, "result": "1"}
```

### Arduino

Uses `arduino-cli` for compilation and upload. Boards are auto-detected via `arduino-cli board list`.

### STM32/Nucleo

Uses `probe-rs` for flash and debug operations:

```bash
probe-rs run --chip STM32F401RETx firmware.elf
```

### Raspberry Pi GPIO

Direct sysfs interface (`/sys/class/gpio/`). No flash support — GPIO read/write only.

## Agent Tools

When hardware is enabled, the agent gains access to:

| Tool | Description |
|------|-------------|
| `hardware_info` | List discovered boards and capabilities |
| `hardware_memory` | Read board memory/registers |
| `i2c` | I2C bus read/write operations |
| `spi` | SPI bus read/write operations |

## Security

Serial port access is restricted to known device paths:
- `/dev/ttyACM*`, `/dev/ttyUSB*` (Linux)
- `/dev/tty.usbmodem*`, `/dev/cu.usbmodem*` (macOS)
- `/dev/tty.usbserial*`, `/dev/cu.usbserial*` (macOS)

## Hotplug Monitoring (Linux)

`nullclaw hardware monitor` uses `udevadm` to watch for USB device events in real time. Events include device add, remove, and change with VID/PID identification.

## Related

- [Architecture](./architecture.md) — Peripheral vtable design
- [Configuration](./configuration.md) — Full config reference
