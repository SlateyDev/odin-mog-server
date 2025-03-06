package common

import "core:sys/windows"

os_config :: proc() {
	windows.SetConsoleOutputCP(.UTF8)
}
