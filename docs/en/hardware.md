# Hardware & Peripherals

NullClaw can discover and interact with microcontroller boards over USB. Only
discovery is implemented in the CLI today — see [Not yet
implemented](#not-yet-implemented) below.

## CLI Commands

```bash
nullclaw hardware scan             # Discover connected boards
```

### Not yet implemented

Two subcommands are accepted but are placeholders. They print a message and do
not perform the action:

| Command | Current behavior | Source |
|---------|------------------|--------|
| `nullclaw hardware flash <path>` | Prints the firmware path, then `Flash not yet implemented.` | `src/main.zig` `runHardware` |
| `nullclaw hardware monitor` | Prints `Monitor not yet implemented.` and exits. Does **not** invoke `udevadm` and does not watch for hotplug events. | `src/main.zig` `runHardware` |

Do not script against either command; neither performs I/O. Use `arduino-cli` or
`probe-rs` directly for flashing (see [Peripheral Drivers](#peripheral-drivers)).

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

When `hardware.boards` is configured, `allTools` registers:

| Tool | Description |
|------|-------------|
| `hardware_board_info` | List discovered boards and capabilities |
| `hardware_memory` | Read board memory/registers |
| `i2c` | I2C bus read/write operations |

The SPI bus driver exists as `src/tools/spi.zig` and is importable, but it is
**not** registered by `allTools` and is therefore not available to the agent.
Treat `spi` as a library capability, not a shipped tool.

Note the tool name is `hardware_board_info`, not `hardware_info` — the
implementation file is `src/tools/hardware_info.zig`, which is a common source
of confusion.

The bare `hardware` CLI subcommand and the peripheral drivers are standalone
implementations; they are not gated on the agent tool registration above.

## Security

Serial port access is restricted to known device paths:
- `/dev/ttyACM*`, `/dev/ttyUSB*` (Linux)
- `/dev/tty.usbmodem*`, `/dev/cu.usbmodem*` (macOS)
- `/dev/tty.usbserial*`, `/dev/cu.usbserial*` (macOS)

## Hotplug Monitoring (Linux)

Not implemented. `nullclaw hardware monitor` is a placeholder that prints a
message and exits — it does not invoke `udevadm`, subscribe to netlink events,
or emit device add/remove/change notifications. Watch USB hotplug externally
(e.g. a `udev` rule or `udevadm monitor`) if you need that.

## Related

- [Architecture](./architecture.md) — Peripheral vtable design
- [Configuration](./configuration.md) — Full config reference
